"""Licences declared as prose rather than as an SPDX identifier.

An SBOM states a licence in whichever form its generator reached for, and
Maven-sourced documents overwhelmingly carry the prose name from a POM's
`<licenses>` block: "The Apache Software License, Version 2.0" rather than
`Apache-2.0`. Those were reported as unresolvable, so a document that named its
licence perfectly clearly counted as not having declared one.

The same licence is written several ways across POMs -- with and without a
leading "The", with "Version 2.0" or ", version 2.0" or bare "2.0", with
"Software" in the middle or not. Listing every spelling would be an open-ended
table, so the spelling is normalised away and matched against the alias table
that already existed.

This is normalisation, not inference. The alias still has to be there: nothing
here makes "BSD" mean `BSD-3-Clause`.
"""
import pytest

from ossbomer.core.ir import Component
from ossbomer.core.licenses import (
    AMBIGUOUS,
    AMBIGUOUS_NAMES,
    SOURCE_NAME,
    UNRESOLVED,
    VIA_ALIAS,
    VIA_DESCRIPTIVE,
    VIA_EXPRESSION,
    _tables,
    descriptive_key,
    normalize,
    reset_caches,
)
from ossbomer.core.validators import ValidatorContext, get

# ---- the spellings from the field --------------------------------------------
# Every one of these was observed in a real SBOM; they are the issue's own table.

@pytest.mark.parametrize("raw,expected", [
    ("MIT License", "MIT"),
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("The Apache License, Version 2.0", "Apache-2.0"),
    ("The Apache Software License, Version 2.0", "Apache-2.0"),
    ("The Apache Software License, version 2.0", "Apache-2.0"),
])
def test_prose_licence_names_resolve(raw, expected):
    assert normalize(raw, SOURCE_NAME).normalized == expected


@pytest.mark.parametrize("raw", [
    "the apache software license, version 2.0",
    "THE APACHE SOFTWARE LICENSE, VERSION 2.0",
    "The  Apache   Software  License ,  Version  2.0",
    "The Apache Software License Version 2.0",
    "Apache Software License, Version 2.0",
])
def test_case_spacing_and_punctuation_do_not_matter(raw):
    """Case, run-together whitespace, the comma before "Version" and the leading
    "The" are all noise. One alias entry has to serve every spelling of it, or
    the table grows without end."""
    assert normalize(raw, SOURCE_NAME).normalized == "Apache-2.0"


def test_the_method_records_how_it_matched(overlay):
    """A prose match is not the same event as an exact alias hit, and the record
    of what happened is what lets a rule tell them apart later.

    Exercised through an overlay rather than a shipped licence. This asserted
    that "The Apache License, Version 2.0" matched by descriptive key, which was
    true until ospac 1.7.0 added that exact spelling to its aliases -- then it
    matched at the exact step instead and the test failed, on a release nobody
    here made.

    Which path resolves a real licence is ospac's data to decide and may change
    with any release. Whether the two paths are told apart is this module's
    behaviour, so the fixture is local and the assertion is stable.
    """
    overlay('aliases:\n  "zzz test licence 1.0": "LicenseRef-ZZZ"\n')
    assert normalize("zzz test licence 1.0", SOURCE_NAME).method == VIA_ALIAS
    assert normalize("The ZZZ Test Licence, Version 1.0", SOURCE_NAME).method == VIA_DESCRIPTIVE
    assert normalize("Apache-2.0", SOURCE_NAME).method == VIA_EXPRESSION


# ---- what must still not resolve ----------------------------------------------
# The point of the whole module: a confident wrong identifier is worse than
# reporting that the text could not be resolved.

@pytest.mark.parametrize("raw", [
    "BSD",                      # which of the four?
    "GPL",                      # denylisted upstream; must stay refused
    "Apache",                   # no version
    "GNU General Public License",  # no version
    "BSD-like",
    "Public Domain",
    "Proprietary",
    "The License",
    "Version 2.0",              # a version and nothing else
    "The",                      # what stripping "The" must not reduce a name to
    "",
])
def test_names_that_identify_nothing_stay_unresolved(raw):
    assert normalize(raw, SOURCE_NAME).normalized is None


def test_stripping_the_cannot_manufacture_a_match():
    """"The" is stripped from both sides of the comparison, so a name that is
    *only* noise must not collapse onto a real alias key."""
    for raw in ("The", "The ", "the the", "The License"):
        assert normalize(raw, SOURCE_NAME).normalized is None


# ---- named, but not identified ------------------------------------------------

AMBIGUOUS_CASES = [
    ("GNU LESSER GENERAL PUBLIC LICENSE, Version 2.1", "LGPL-2.1"),
    ("GNU Lesser General Public License, Version 2.1", "LGPL-2.1"),
    ("The GNU General Public License, Version 3.0", "GPL-3.0"),
    ("GNU Affero General Public License, Version 3.0", "AGPL-3.0"),
]


@pytest.mark.parametrize("raw,family", AMBIGUOUS_CASES)
def test_a_gnu_licence_name_is_ambiguous_rather_than_unresolved(raw, family):
    """It names the licence and the version, and still is not an identifier.

    `-only` versus `-or-later` is the copyright holder's grant, which the
    licence's own name does not carry. Picking either would assert something the
    document never said -- but "I do not recognise this" is the wrong thing to
    tell someone whose document is perfectly legible. It is its own outcome.
    """
    declaration = normalize(raw, SOURCE_NAME)
    assert declaration.normalized is None
    assert declaration.method == AMBIGUOUS
    assert declaration.ambiguous is True


def test_an_unrecognised_name_is_not_ambiguous():
    """The two states must stay distinguishable, or the distinction buys
    nothing."""
    declaration = normalize("Totally Made Up License", SOURCE_NAME)
    assert declaration.method == UNRESOLVED
    assert declaration.ambiguous is False


def test_an_explicit_gnu_identifier_still_resolves():
    """Ambiguity is a property of the prose name, not of the licence. A document
    that says which one it means is answered."""
    for raw, expected in [("LGPL-2.1-only", "LGPL-2.1-only"),
                          ("LGPL-2.1-or-later", "LGPL-2.1-or-later"),
                          ("GPL-3.0-or-later", "GPL-3.0-or-later")]:
        assert normalize(raw, SOURCE_NAME).normalized == expected


# ---- what the user is told ----------------------------------------------------

def _message(raw):
    component = Component(name="c", license_declarations=[normalize(raw, SOURCE_NAME)])
    ok, message = get("license_spdx_normalized")(
        None, ValidatorContext(None, component, ""), {})
    return ok, message


def test_the_ambiguous_message_names_the_choice_to_be_made():
    """The two failures need different fixes -- add the identifier you meant,
    versus this text names no licence I know -- so they must not read the same.
    """
    ok, message = _message("GNU LESSER GENERAL PUBLIC LICENSE, Version 2.1")
    assert ok is False
    assert "LGPL-2.1-only or LGPL-2.1-or-later" in message
    assert "later versions" in message


def test_the_unresolved_message_is_the_other_one():
    ok, message = _message("Totally Made Up License")
    assert ok is False
    assert "does not resolve to an SPDX license" in message
    assert "later versions" not in message


def test_a_resolvable_prose_name_produces_no_finding():
    assert _message("The Apache Software License, Version 2.0") == (True, "")


# ---- the key function ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("The Apache Software License, Version 2.0", "apache software license 2.0"),
    ("Apache License, Version 2.0", "apache license 2.0"),
    ("  MIT   License  ", "mit license"),
    ("GNU LESSER GENERAL PUBLIC LICENSE, Version 2.1",
     "gnu lesser general public license 2.1"),
    ("Eclipse Public License - v 2.0", "eclipse public license - v 2.0"),
    ("", ""),
])
def test_descriptive_key_normalises_the_spelling(raw, expected):
    assert descriptive_key(raw) == expected


def test_descriptive_key_is_idempotent():
    """It is applied to both sides of the lookup, and to alias keys that may
    already be in normalised form. Applying it twice must not move."""
    for raw in ("The Apache Software License, Version 2.0", "MIT License", "", "The"):
        once = descriptive_key(raw)
        assert descriptive_key(once) == once


def test_a_theatre_licence_keeps_its_the():
    """`^the\\s+` only strips a leading article, not the letters "the" wherever
    they appear."""
    assert descriptive_key("Theatre Public License") == "theatre public license"

# ---- adopter overlays --------------------------------------------------------
# The layer an adopter controls. Normalising the spelling must not let a
# document slip past what they declared -- both of these leaked when the
# descriptive table was derived from the merged aliases afterwards instead of
# built in the same layering pass.

@pytest.fixture
def overlay(tmp_path, monkeypatch):
    def _write(body):
        path = tmp_path / "overlay.yaml"
        path.write_text(body)
        monkeypatch.setenv("OSSBOMER_LICENSE_ALIASES", str(path))
        reset_caches()
        return path
    yield _write
    monkeypatch.delenv("OSSBOMER_LICENSE_ALIASES", raising=False)
    reset_caches()


@pytest.mark.parametrize("raw", [
    "Eclipse Public License 2.0",
    "The Eclipse Public License 2.0",
    "Eclipse Public License, Version 2.0",
    "THE ECLIPSE PUBLIC LICENSE, VERSION 2.0",
])
def test_a_denylisted_licence_cannot_be_reached_by_respelling_it(overlay, raw):
    """A denylist that only stops the exact string is not a denylist.

    Refusing "Eclipse Public License 2.0" while resolving "The Eclipse Public
    License 2.0" is precisely the confident resolution the adopter wrote the
    entry to prevent.
    """
    overlay('never_resolve: ["eclipse public license 2.0"]\n')
    assert normalize(raw, SOURCE_NAME).normalized is None


@pytest.mark.parametrize("raw", [
    "apache software license, version 2.0",
    "The Apache Software License, Version 2.0",
    "The Apache Software License, version 2.0",
    "Apache Software License 2.0",
])
def test_an_overlay_override_applies_to_every_spelling(overlay, raw):
    """Overlays win on conflict, and that has to hold in the descriptive
    dimension too. Half-applying gave the same licence two identifiers in one
    run, decided by a leading "The"."""
    overlay('aliases:\n  "apache software license, version 2.0": "LicenseRef-Corp"\n')
    assert normalize(raw, SOURCE_NAME).normalized == "LicenseRef-Corp"


def test_an_overlay_does_not_leak_into_the_shipped_tables(overlay):
    """The override is scoped to the overlay being present."""
    overlay('aliases:\n  "apache software license, version 2.0": "LicenseRef-Corp"\n')
    assert normalize("MIT License", SOURCE_NAME).normalized == "MIT"


# ---- drift guards ------------------------------------------------------------
# Both hold today by accident of the current data. Neither is asserted anywhere
# else, and an ospac release could break either silently.

def test_no_two_aliases_collapse_to_one_descriptive_key_with_different_values():
    """`descriptive_key` is many-to-one. Where two alias spellings collapse onto
    the same key, the later layer wins -- which is right for an overlay
    overriding a shipped entry, and wrong if two *different* licences in the
    same layer collide. Nothing would report that; this does.
    """
    from collections import defaultdict

    aliases = _tables()[0]
    collapsed = defaultdict(set)
    for key, value in aliases.items():
        collapsed[descriptive_key(key)].add(value)
    clashes = {k: sorted(v) for k, v in collapsed.items() if len(v) > 1}
    assert not clashes, f"descriptive-key collisions between different licences: {clashes}"


def test_no_ambiguous_name_is_also_a_resolvable_alias():
    """Ambiguity is checked before the descriptive lookup, so this cannot cause
    a wrong answer today. It would still mean the two tables disagree about the
    same string, which is worth knowing before it becomes load-bearing.
    """
    descriptive_aliases = _tables()[3]
    overlap = sorted(set(AMBIGUOUS_NAMES) & set(descriptive_aliases))
    assert not overlap, f"named as ambiguous and resolvable at once: {overlap}"


@pytest.mark.parametrize("raw", [
    # The spelling that hits the overlay's key exactly, so the alias lookup can
    # answer before any guard does. The first version of this test used only the
    # spelling below, which misses that path -- it passed without the guard
    # being in the right place, which is a test passing for the wrong reason.
    "GNU Lesser General Public License 2.1",
    "gnu lesser general public license 2.1",
    "GNU Lesser General Public License, Version 2.1",
    "The GNU Lesser General Public License, Version 2.1",
])
def test_ambiguity_wins_over_a_conflicting_alias(overlay, raw):
    """No lookup may answer an ambiguous name with a confident identifier.

    An alias -- shipped or adopter-declared -- that claims one of these names
    would otherwise resolve it under the spelling that matches the alias key and
    report the ambiguity under every other spelling: the same document, two
    answers, decided by punctuation.
    """
    overlay('aliases:\n  "gnu lesser general public license 2.1": "LGPL-2.1-only"\n')
    declaration = normalize(raw, SOURCE_NAME)
    assert declaration.normalized is None
    assert declaration.ambiguous is True


@pytest.mark.parametrize("raw", [
    "MIT License",
    "The MIT License",     # a shipped alias, which the denylist must still beat
    "the mit license",
    "The MIT License, Version 1.0",
])
def test_a_denylist_beats_a_shipped_alias(overlay, raw):
    """The denylist has to outrank every table, not just sit above the one added
    last. `never_resolve: ["MIT License"]` refused that string and then resolved
    "The MIT License" through a curated alias further down the pipeline.
    """
    overlay('never_resolve: ["MIT License"]\n')
    assert normalize(raw, SOURCE_NAME).normalized is None


@pytest.mark.parametrize("raw,expected", [
    ("LGPL-2.1-only", "LGPL-2.1-only"),
    ("LGPL-2.1-or-later", "LGPL-2.1-or-later"),
    ("LGPL-2.1", "LGPL-2.1-only"),      # deprecated, mapped forward by SPDX itself
    ("GPL-3.0-or-later", "GPL-3.0-or-later"),
])
def test_an_identifier_outranks_the_ambiguity_guard(raw, expected):
    """Ambiguity is a property of the prose name, not of the licence.

    The guard sits below the expression step precisely so a document that says
    which identifier it means is answered rather than second-guessed.
    """
    assert normalize(raw, SOURCE_NAME).normalized == expected
