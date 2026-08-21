"""License normalization to SPDX.

An SBOM states a license in whichever slot its generator reached for, and the
ecosystems that produce them invented their own operators along the way. Policy
is keyed on SPDX identifiers, so everything has to land there or be reported as
not landing there. Nothing is guessed.
"""
import json

import pytest

from ossbomer.core.licenses import (
    DECLARED_UNKNOWN,
    SOURCE_ID,
    SOURCE_NAME,
    UNRESOLVED,
    VIA_ALIAS,
    VIA_EXPRESSION,
    VIA_SEPARATOR,
    normalize,
)
from ossbomer.core.parsers import parse_file
from ossbomer.core.runner import run


@pytest.mark.parametrize("raw,expected", [
    # Plain identifiers and case.
    ("MIT", "MIT"), ("mit", "MIT"), ("apache-2.0", "Apache-2.0"),
    # The "+" suffix and the modern spellings mean the same thing.
    ("GPL-2.0+", "GPL-2.0-or-later"),
    ("GPL-2.0-or-later", "GPL-2.0-or-later"),
    ("LGPL-2.1+", "LGPL-2.1-or-later"),
    ("GPL-3.0-only", "GPL-3.0-only"),
    # Operators in any case, and exceptions.
    ("MIT or Apache-2.0", "MIT OR Apache-2.0"),
    ("MIT and Apache-2.0", "MIT AND Apache-2.0"),
    ("Apache-2.0 with LLVM-exception", "Apache-2.0 WITH LLVM-exception"),
    # Parenthesised and nested.
    ("(MIT OR Apache-2.0)", "MIT OR Apache-2.0"),
    ("MIT OR (Apache-2.0 AND BSD-3-Clause)", "MIT OR (Apache-2.0 AND BSD-3-Clause)"),
])
def test_spdx_spellings_normalize(raw, expected):
    d = normalize(raw, SOURCE_ID)
    assert d.normalized == expected
    assert d.method == VIA_EXPRESSION


def test_npm_double_pipe_is_or():
    """npm documents `||` as OR, so it translates directly."""
    d = normalize("MIT || Apache-2.0", SOURCE_NAME)
    assert d.normalized == "MIT OR Apache-2.0"
    assert d.method == VIA_SEPARATOR


@pytest.mark.parametrize("raw", ["MIT/Apache-2.0", "MIT,Apache-2.0", "MIT; Apache-2.0"])
def test_ambiguous_separators_resolve_the_safe_way(raw):
    """A bare list does not say whether both licenses apply or either does.

    Policy takes the least restrictive operand of an OR and the most restrictive
    of an AND, so reading a list as OR when it meant AND under-reports
    obligations and can pass something that should have been denied. Reading it
    as AND over-reports, which surfaces for review instead. The declaration
    records that a separator was interpreted so a profile can flag it.
    """
    d = normalize(raw, SOURCE_NAME)
    assert d.normalized == "MIT AND Apache-2.0"
    assert d.method == VIA_SEPARATOR


@pytest.mark.parametrize("raw,expected", [
    ("Apache 2", "Apache-2.0"), ("Apache2", "Apache-2.0"),
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("The MIT License", "MIT"), ("Expat", "MIT"),
    ("New BSD", "BSD-3-Clause"), ("Simplified BSD", "BSD-2-Clause"),
])
def test_curated_aliases_resolve(raw, expected):
    d = normalize(raw, SOURCE_NAME)
    assert d.normalized == expected
    assert d.method == VIA_ALIAS


@pytest.mark.parametrize("raw", [
    "BSD",            # 2-clause or 3-clause; the choice changes obligations
    "GPL",            # version and only/or-later both unstated
    "LGPL",
    "Apache",         # 1.0, 1.1 and 2.0 all exist
    "Public Domain",  # not a license; CC0-1.0 is a dedication, not a synonym
    "BSD-like",
    "MIT (http://mootools.net/license.txt)",
    "see LICENSE file",
])
def test_ambiguous_text_is_never_guessed(raw):
    """The whole point of the alias table is what it refuses.

    Resolving "BSD" to BSD-3-Clause would produce a confident answer the
    document does not support, which is worse than reporting it unresolved.
    """
    d = normalize(raw, SOURCE_NAME)
    assert d.normalized is None
    assert d.method == UNRESOLVED
    assert d.effective == raw  # the raw text survives for policies matching it


@pytest.mark.parametrize("raw", ["NOASSERTION", "NONE", "", "   "])
def test_explicit_unknown_is_distinguished_from_unresolvable(raw):
    """"I do not know" is a different statement from text nobody can parse, and
    CISA 2026 asks authors to make exactly that statement."""
    d = normalize(raw, SOURCE_NAME)
    assert d.declared_unknown
    assert not d.resolved
    assert d.method == DECLARED_UNKNOWN


def test_valid_expression_in_the_free_text_slot_is_flagged():
    """A consumer reading only `expression` and `license.id` would miss this
    license entirely, even though it is perfectly well formed."""
    misplaced = normalize("MPL-2.0 OR Apache-2.0", SOURCE_NAME)
    assert misplaced.resolved
    assert misplaced.misplaced

    proper = normalize("MPL-2.0 OR Apache-2.0", SOURCE_ID)
    assert proper.resolved
    assert not proper.misplaced


def test_unresolvable_text_is_not_reported_as_misplaced():
    assert not normalize("BSD-like", SOURCE_NAME).misplaced


# ---- through the parser and the engine --------------------------------------

def _write(tmp_path, components):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"timestamp": "2026-07-30T00:00:00Z"},
           "components": components, "dependencies": []}
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def test_parser_records_which_slot_each_license_came_from(tmp_path):
    path = _write(tmp_path, [
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
         "licenses": [{"expression": "MIT OR Apache-2.0"}]},
        {"type": "library", "name": "b", "version": "1", "purl": "pkg:npm/b@1",
         "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "c", "version": "1", "purl": "pkg:npm/c@1",
         "licenses": [{"license": {"name": "BSD-like"}}]},
    ])
    sbom = parse_file(path)
    got = {c.name: c.license_declarations[0] for c in sbom.components}
    assert got["a"].source == "expression"
    assert got["b"].source == "id"
    assert got["c"].source == "name"
    assert got["c"].normalized is None


def test_the_flat_list_carries_the_normalized_form(tmp_path):
    """`licenses` is what policy and the older rules read, so normalization has
    to reach it. Before this, ospac received "Apache 2" verbatim."""
    path = _write(tmp_path, [
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
         "licenses": [{"license": {"name": "Apache 2"}}]}])
    (component,) = parse_file(path).components
    assert component.licenses == ["Apache-2.0"]


def test_unresolvable_text_still_reaches_policy_verbatim(tmp_path):
    """A policy may list the exact string, and "unknown" is a reviewable answer.
    Dropping it would silently remove a license from consideration."""
    path = _write(tmp_path, [
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
         "licenses": [{"license": {"name": "BSD-like"}}]}])
    (component,) = parse_file(path).components
    assert component.licenses == ["BSD-like"]


def test_profile_reports_unresolvable_licenses(tmp_path):
    path = _write(tmp_path, [
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
         "supplier": {"name": "ACME"},
         "licenses": [{"license": {"name": "BSD-like"}}]}])
    (result,) = run(path, ["cisa-2026-min"])
    finding = next(f for f in result.findings
                   if f.rule_id == "cisa26-component-license")
    assert finding.verdict.value == "FAIL"
    assert "does not resolve" in finding.message
    # It must not be described as bad expression syntax: the `name` slot never
    # claimed to hold an expression.
    assert "not a valid SPDX license expression" not in finding.message


# ---- extensibility -----------------------------------------------------------

def test_bare_gpl_is_refused_despite_upstream_resolving_it():
    """license-expression maps bare "GPL" to GPL-1.0-or-later, because that is
    what the deprecated key meant. Nobody writing "GPL" today means version 1.0,
    so taking that mapping would hand back a confident wrong answer and policy
    would evaluate the wrong license."""
    d = normalize("GPL", SOURCE_NAME)
    assert d.normalized is None
    assert d.method == UNRESOLVED


def test_an_overlay_file_can_add_aliases(tmp_path, monkeypatch):
    """License spellings drift, so the tables extend without editing the
    package, the same way profiles and validators already do."""
    from ossbomer.core.licenses import ENV_ALIASES, reset_caches

    overlay = tmp_path / "acme.yaml"
    overlay.write_text(
        "aliases:\n"
        '  "acme proprietary v2": LicenseRef-ACME-2.0\n'
        '  "BSD": BSD-3-Clause\n'          # override a deliberate refusal
        "never_resolve:\n"
        '  - "MIT"\n'                      # and refuse a shipped mapping
        "separators:\n"
        "  ' plus ': ' AND '\n",
        encoding="utf-8")
    monkeypatch.setenv(ENV_ALIASES, str(overlay))
    reset_caches()
    try:
        assert normalize("ACME Proprietary v2", SOURCE_NAME).normalized == \
            "LicenseRef-ACME-2.0"
        # An overlay wins over a built-in refusal, in both directions.
        assert normalize("BSD", SOURCE_NAME).normalized == "BSD-3-Clause"
        assert normalize("MIT", SOURCE_NAME).normalized is None
        assert normalize("Apache-2.0 plus MIT", SOURCE_NAME).normalized == \
            "Apache-2.0 AND MIT"
    finally:
        monkeypatch.delenv(ENV_ALIASES, raising=False)
        reset_caches()

    # And the built-ins are back once the overlay goes away.
    assert normalize("MIT", SOURCE_NAME).normalized == "MIT"
    assert normalize("BSD", SOURCE_NAME).normalized is None


def test_a_broken_overlay_file_is_an_operator_error(tmp_path, monkeypatch):
    """A file the operator explicitly named must not fail silently, unlike an
    entry point shipped by a third party."""
    from ossbomer.core.licenses import ENV_ALIASES, reset_caches

    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    monkeypatch.setenv(ENV_ALIASES, str(bad))
    reset_caches()
    try:
        with pytest.raises(TypeError, match="mapping"):
            normalize("anything at all", SOURCE_NAME)
    finally:
        monkeypatch.delenv(ENV_ALIASES, raising=False)
        reset_caches()


def test_ospac_alias_api_is_preferred_when_it_exists(monkeypatch):
    """ospac is the source of truth for license metadata across these tools, so
    when it grows a `license_aliases()` function that becomes the supply. Until
    then the shipped license records are read instead, which is a fallback and
    not a contract."""
    import ospac

    from ossbomer.core.licenses import reset_caches

    monkeypatch.setattr(ospac, "license_aliases",
                        lambda: {"ACME House Style v1": "LicenseRef-ACME-1.0"},
                        raising=False)
    reset_caches()
    try:
        assert normalize("acme house style v1", SOURCE_NAME).normalized == \
            "LicenseRef-ACME-1.0"
    finally:
        monkeypatch.delattr(ospac, "license_aliases", raising=False)
        reset_caches()


def test_a_broken_ospac_api_falls_back_rather_than_losing_normalization(monkeypatch):
    import ospac

    from ossbomer.core.licenses import reset_caches

    def exploding():
        raise RuntimeError("upstream changed shape")

    monkeypatch.setattr(ospac, "license_aliases", exploding, raising=False)
    reset_caches()
    try:
        # Falls back to the shipped records, which carry the official long name.
        assert normalize("Apache License 2.0", SOURCE_NAME).normalized == "Apache-2.0"
    finally:
        monkeypatch.delattr(ospac, "license_aliases", raising=False)
        reset_caches()


def test_normalization_works_without_ospac_at_all(monkeypatch):
    """ospac is the [oslc] extra, but normalization is used by every profile.
    The built-in tables have to stand alone."""
    import builtins

    from ossbomer.core.licenses import reset_caches

    real_import = builtins.__import__

    def no_ospac(name, *args, **kwargs):
        if name == "ospac":
            raise ImportError("ospac not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_ospac)
    reset_caches()
    try:
        assert normalize("Apache 2", SOURCE_NAME).normalized == "Apache-2.0"
        assert normalize("MIT", SOURCE_NAME).normalized == "MIT"
        assert normalize("BSD", SOURCE_NAME).normalized is None
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        reset_caches()

# ---- the promise must be ours to keep ----------------------------------------

def test_every_refused_name_is_refused_by_us_not_by_upstreams_omission():
    """`test_ambiguous_text_is_never_guessed` above states a promise: these names
    are never guessed at. Most of them used to hold only because ospac did not
    happen to carry them.

    That is not a promise, it is a coincidence. ospac is actively adding folk
    spellings (SemClone/ospac#88, #89), and a release adding `bsd ->
    BSD-3-Clause` would have made `normalize("BSD")` return a confident wrong
    answer -- with the test failing *after* the behaviour changed rather than
    instead of it.

    Each family name is now on the denylist, which is checked before any lookup,
    so no upstream data can reach them.
    """
    from ossbomer.core.licenses import NEVER_RESOLVE

    family_names = ["gpl", "lgpl", "agpl", "bsd", "apache", "mpl", "epl", "cddl",
                    "public domain", "proprietary", "commercial", "bsd-like"]
    missing = [n for n in family_names if n not in NEVER_RESOLVE]
    assert not missing, f"promised as never-guessed but not denylisted: {missing}"


def test_the_denylist_stops_the_tool_guessing_not_the_adopter_deciding(tmp_path,
                                                                      monkeypatch):
    """Who the refusal is aimed at.

    The denylist exists so *this tool* never invents an answer, and so upstream
    data cannot quietly start inventing one on its behalf. It is not there to
    overrule the person running it: an adopter who maps "bsd" has made a
    decision about their own corpus, and overlays win on conflict.

    So an explicit overlay alias lifts the refusal for that name and nothing
    else does -- not the shipped tables, not ospac's.
    """
    from ossbomer.core.licenses import reset_caches

    overlay = tmp_path / "aliases.yaml"
    overlay.write_text('aliases:\n  "bsd": "BSD-3-Clause"\n')
    monkeypatch.setenv("OSSBOMER_LICENSE_ALIASES", str(overlay))
    reset_caches()
    try:
        # The name the adopter mapped: their call, honoured.
        assert normalize("BSD", SOURCE_NAME).normalized == "BSD-3-Clause"
        # A name they said nothing about: still refused.
        assert normalize("Apache", SOURCE_NAME).normalized is None
        assert normalize("MIT", SOURCE_NAME).normalized == "MIT"
    finally:
        monkeypatch.delenv("OSSBOMER_LICENSE_ALIASES", raising=False)
        reset_caches()


def test_never_resolve_beats_an_alias_in_the_same_overlay(tmp_path, monkeypatch):
    """Both directions in one file. `never_resolve` is the more specific
    statement, so it wins over an alias for the same name."""
    from ossbomer.core.licenses import reset_caches

    overlay = tmp_path / "aliases.yaml"
    overlay.write_text('aliases:\n  "bsd": "BSD-3-Clause"\n'
                       'never_resolve:\n  - "bsd"\n')
    monkeypatch.setenv("OSSBOMER_LICENSE_ALIASES", str(overlay))
    reset_caches()
    try:
        assert normalize("BSD", SOURCE_NAME).normalized is None
    finally:
        monkeypatch.delenv("OSSBOMER_LICENSE_ALIASES", raising=False)
        reset_caches()


def test_ospac_data_cannot_lift_a_refusal(tmp_path, monkeypatch):
    """The case this hardening is for.

    ospac is filling in folk spellings (SemClone/ospac#88, #89). A release
    adding `bsd -> BSD-3-Clause` must not make this tool start answering "BSD",
    because nothing about that document changed -- only somebody else's data.
    """
    import functools

    import ossbomer.core.licenses as L
    from ossbomer.core.licenses import reset_caches

    # lru_cache-wrapped: `reset_caches` calls `.cache_clear()` on this, so a
    # bare lambda would fail on teardown rather than on the assertion.
    fake = functools.lru_cache(maxsize=1)(
        lambda: {"bsd": "BSD-3-Clause", "apache": "Apache-2.0"})
    monkeypatch.setattr(L, "_ospac_aliases", fake)
    reset_caches()
    try:
        assert normalize("BSD", SOURCE_NAME).normalized is None
        assert normalize("Apache", SOURCE_NAME).normalized is None
    finally:
        reset_caches()


def test_denylisting_a_family_does_not_refuse_its_versioned_members():
    """"bsd" is refused; `BSD-3-Clause` is a licence and must not be."""
    for raw in ("BSD-3-Clause", "BSD-2-Clause", "Apache-2.0", "MPL-2.0",
                "EPL-2.0", "AGPL-3.0-only", "LGPL-2.1-or-later"):
        assert normalize(raw, SOURCE_NAME).normalized == raw

@pytest.mark.parametrize("raw", [
    "Apache License", "The Apache License", "BSD License", "GPL License",
    "GNU General Public License", "GNU Lesser General Public License",
])
def test_a_family_written_out_is_refused_like_the_bare_token(raw):
    """`descriptive_key` strips a leading "The" and the word "Version". It does
    not strip "License", so "Apache License" is a different key from "apache".

    Denylisting only the bare token left the spelling SBOMs actually use
    protected by upstream omission -- the exact hole this list was widened to
    close, one word further along.
    """
    assert normalize(raw, SOURCE_NAME).normalized is None


@pytest.mark.parametrize("raw,expected", [
    ("MIT License", "MIT"),          # one licence; the word adds no ambiguity
    ("The MIT License", "MIT"),
    ("ISC License", "ISC"),
    ("Zlib License", "Zlib"),
    ("Apache License 2.0", "Apache-2.0"),        # a version makes it specific
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("Eclipse Public License 1.0", "EPL-1.0"),
])
def test_refusing_a_family_does_not_refuse_a_licence(raw, expected):
    """The denylist must cost nothing that names one licence.

    "MIT License" names exactly one, and a version makes any family specific
    again. Widening the list is only safe if these keep working.
    """
    assert normalize(raw, SOURCE_NAME).normalized == expected


def test_a_same_overlay_refusal_survives_every_spelling(tmp_path, monkeypatch):
    """An overlay that maps a name and refuses it in the same file.

    The refusal was subtracted in the exact key space only, so
    `never_resolve: ["The MIT License"]` left the descriptive key lifted and
    "MIT License" resolved through the alias the same overlay had just refused.
    """
    from ossbomer.core.licenses import reset_caches

    overlay = tmp_path / "aliases.yaml"
    overlay.write_text('aliases:\n  "The MIT License": "LicenseRef-Corp"\n'
                       'never_resolve:\n  - "The MIT License"\n')
    monkeypatch.setenv("OSSBOMER_LICENSE_ALIASES", str(overlay))
    reset_caches()
    try:
        for raw in ("The MIT License", "MIT License", "the mit license"):
            assert normalize(raw, SOURCE_NAME).normalized is None, raw
    finally:
        monkeypatch.delenv("OSSBOMER_LICENSE_ALIASES", raising=False)
        reset_caches()


def test_ospac_cannot_lift_a_family_refusal_by_writing_it_out(monkeypatch):
    """The upstream-drift path, one word further along than the first test.

    ospac adding `apache license -> Apache-2.0` must not make this tool answer
    "Apache License", for the same reason `apache` must not.
    """
    import functools

    import ossbomer.core.licenses as L
    from ossbomer.core.licenses import reset_caches

    fake = functools.lru_cache(maxsize=1)(
        lambda: {"apache license": "Apache-2.0", "bsd license": "BSD-3-Clause"})
    monkeypatch.setattr(L, "_ospac_aliases", fake)
    reset_caches()
    try:
        assert normalize("Apache License", SOURCE_NAME).normalized is None
        assert normalize("BSD License", SOURCE_NAME).normalized is None
    finally:
        reset_caches()

# The families whose SPDX identifiers differ only by version. Named once here,
# because a name from one of these without a version identifies a family and not
# a licence -- which is the whole criterion for refusing it.
VERSIONED_FAMILIES = {
    "Apache": ["apache", "apache license", "apache software license"],
    "BSD": ["bsd", "bsd license"],
    "GPL": ["gpl", "gpl license", "gnu general public license"],
    "LGPL": ["lgpl", "lgpl license", "gnu lesser general public license",
             "gnu library general public license"],
    "AGPL": ["agpl", "agpl license", "gnu affero general public license"],
    "MPL": ["mpl", "mpl license", "mozilla public license"],
    "EPL": ["epl", "epl license", "eclipse public license"],
    "CDDL": ["cddl", "cddl license",
             "common development and distribution license"],
}


@pytest.mark.parametrize("family,spellings", sorted(VERSIONED_FAMILIES.items()))
def test_every_versioned_family_is_refused_unversioned(family, spellings):
    """Generated from the shapes, not from whichever spelling someone remembered.

    Three rounds of review found the denylist short by one spelling each time:
    the abbreviation, then "<family> License", then the written-out name. Each
    fix closed the example and left the class, which is what enumeration does.

    A name from a family whose SPDX identifiers differ only by version, carrying
    no version, identifies a family and not a licence. Every spelling of that
    shape must be refused, and a leading "The" must not lift it.
    """
    for spelling in spellings:
        for raw in (spelling, spelling.title(), f"The {spelling}",
                    spelling.upper()):
            assert normalize(raw, SOURCE_NAME).normalized is None, (
                f"{raw!r} names the {family} family without a version and "
                f"resolved anyway")


@pytest.mark.parametrize("family,spellings", sorted(VERSIONED_FAMILIES.items()))
def test_adding_a_version_makes_a_family_name_specific_again(family, spellings):
    """The other half, and the reason the refusal is safe.

    Refusing a family must never refuse a licence. A version turns any of these
    back into a name that identifies one thing, and those must keep resolving --
    that is what most real SBOMs actually carry.
    """
    versioned = {
        "Apache": "Apache License 2.0",
        "BSD": "BSD-3-Clause",
        "GPL": "GPL-3.0-or-later",
        "LGPL": "LGPL-2.1-or-later",
        "AGPL": "AGPL-3.0-only",
        "MPL": "MPL-2.0",
        "EPL": "Eclipse Public License 2.0",
        "CDDL": "CDDL-1.0",
    }[family]
    assert normalize(versioned, SOURCE_NAME).normalized is not None, versioned
