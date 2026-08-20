"""Component identifiers: purl and CPE, on both formats.

Two defects met here. The SPDX parser read `external_references` looking only for
`purl`, so `Component.cpe` was None for every SPDX document ever parsed -- the
same component read from SPDX and from CycloneDX produced different IR. And
`bsi-component-identifier` matched on `field: purl` while citing BSI TR-03183-2
§5.2.4, "Other unique identifiers (CPE or purl)", so a component identified
solely by a CPE failed a requirement it met.

Either fix alone leaves the bug: populating `cpe` does nothing while the rule
never looks at it, and widening the rule finds nothing while SPDX never fills the
field.
"""
import json
from types import SimpleNamespace

import pytest

from ossbomer.core.engine import _extract_any
from ossbomer.core.parsers import parse_file
from ossbomer.core.profile import Rule
from ossbomer.core.runner import run
from ossbomer.core.validators import _REGISTRY, ValidatorContext, _split_unescaped

CPE23 = "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*"
CPE22 = "cpe:/a:vendor:prod:1.0"
PURL = "pkg:npm/prod@1.0"

RULE = "bsi-component-identifier"
PROFILE = "bsi-tr-03183-v2.1"


def _spdx(tmp_path, *packages):
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "identifiers",
        "documentNamespace": "https://example.com/identifiers",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t-1.0"]},
        "packages": list(packages),
    }
    path = tmp_path / "identifiers.spdx.json"
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


def _pkg(name, *refs):
    return {"SPDXID": f"SPDXRef-{name}", "name": name, "versionInfo": "1.0",
            "downloadLocation": "NOASSERTION", "externalRefs": list(refs)}


def _ref(ref_type, locator):
    category = "PACKAGE-MANAGER" if ref_type == "purl" else "SECURITY"
    return {"referenceCategory": category, "referenceType": ref_type,
            "referenceLocator": locator}


def _cdx(tmp_path, **component):
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
        "components": [{"type": "library", "name": "prod", "version": "1.0", **component}],
    }
    path = tmp_path / "identifiers.cdx.json"
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


def _verdicts(sbom_path, rule_id=RULE):
    (result,) = run(str(sbom_path), [PROFILE])
    return [(f.verdict.value, f.message) for f in result.findings if f.rule_id == rule_id]


# ---- SPDX ingest -------------------------------------------------------------

@pytest.mark.parametrize("ref_type,locator", [("cpe23Type", CPE23), ("cpe22Type", CPE22)])
def test_spdx_security_refs_populate_cpe(tmp_path, ref_type, locator):
    """SPDX 2.3 §7.11.2 defines both bindings and documents in the wild use both.

    Reading only `cpe23Type` would leave every document that declares the older
    URI form looking identifier-less.
    """
    sbom = _spdx(tmp_path, _pkg("p", _ref(ref_type, locator)))
    assert sbom.components[0].cpe == locator


def test_spdx_package_can_carry_both_identifiers(tmp_path):
    """Neither lookup may short-circuit the other. The original loop `break`ed on
    the first purl, which would still have missed a CPE listed after it."""
    sbom = _spdx(tmp_path, _pkg("p", _ref("purl", PURL), _ref("cpe23Type", CPE23)))
    component = sbom.components[0]
    assert (component.purl, component.cpe) == (PURL, CPE23)


def test_spdx_cpe_is_found_when_listed_before_the_purl(tmp_path):
    sbom = _spdx(tmp_path, _pkg("p", _ref("cpe23Type", CPE23), _ref("purl", PURL)))
    component = sbom.components[0]
    assert (component.purl, component.cpe) == (PURL, CPE23)


def test_spdx_purl_only_leaves_cpe_unset(tmp_path):
    """Absent stays absent: the fix must not invent an identifier."""
    sbom = _spdx(tmp_path, _pkg("p", _ref("purl", PURL)))
    assert sbom.components[0].cpe is None


def test_spdx_package_with_no_refs_has_neither(tmp_path):
    sbom = _spdx(tmp_path, _pkg("p"))
    component = sbom.components[0]
    assert (component.purl, component.cpe) == (None, None)


def test_spdx_and_cyclonedx_agree_on_the_same_component(tmp_path):
    """The parity this bug broke. A component carrying both identifiers must
    reach the IR identically whichever format expressed it."""
    from_spdx = _spdx(tmp_path, _pkg("prod", _ref("purl", PURL), _ref("cpe23Type", CPE23)))
    from_cdx = _cdx(tmp_path, purl=PURL, cpe=CPE23)
    for attr in ("name", "version", "purl", "cpe"):
        assert getattr(from_spdx.components[0], attr) == getattr(from_cdx.components[0], attr)


# ---- the BSI rule ------------------------------------------------------------

def test_cpe_only_component_satisfies_the_rule(tmp_path):
    """§5.2.4 accepts "CPE or purl". This component has one."""
    _spdx(tmp_path, _pkg("p", _ref("cpe23Type", CPE23)))
    assert _verdicts(tmp_path / "identifiers.spdx.json") == [("PASS", "ok")]


def test_purl_only_component_still_satisfies_the_rule(tmp_path):
    """The case that already worked, kept so widening the rule cannot regress it."""
    _spdx(tmp_path, _pkg("p", _ref("purl", PURL)))
    assert _verdicts(tmp_path / "identifiers.spdx.json") == [("PASS", "ok")]


def test_component_with_no_identifier_does_not_pass(tmp_path):
    """A rule that passes everything checks nothing.

    WARN rather than FAIL is the clause speaking: §5.2.4 requires the field only
    "if it exists", which is what MUST_WHERE_AVAILABLE encodes. A document that
    never declared an identifier has not violated it.
    """
    _spdx(tmp_path, _pkg("p"))
    (verdict, _), = _verdicts(tmp_path / "identifiers.spdx.json")
    assert verdict == "WARN"


@pytest.mark.parametrize("ref_type,locator", [
    ("cpe23Type", "cpe:2.3:a:too:few:parts"),
    ("purl", "not-a-purl"),
])
def test_malformed_identifiers_fail(tmp_path, ref_type, locator):
    """Present but malformed is a violation, not an absence: the data exists and
    does not "fulfil the requirements of an SBOM format specification"."""
    _spdx(tmp_path, _pkg("p", _ref(ref_type, locator)))
    (verdict, _), = _verdicts(tmp_path / "identifiers.spdx.json")
    assert verdict == "FAIL"


def test_a_valid_cpe_is_not_rejected_for_failing_to_be_a_purl(tmp_path):
    """The trap in the obvious fix. Pairing `fields: [purl, cpe]` with
    `purl_wellformed` widens the lookup and then rejects what it finds."""
    _spdx(tmp_path, _pkg("p", _ref("cpe23Type", CPE23)))
    (_, message), = _verdicts(tmp_path / "identifiers.spdx.json")
    assert "PURL" not in message


# ---- validators --------------------------------------------------------------

def _check(name, value):
    return _REGISTRY[name](value, ValidatorContext(None), {})[0]


@pytest.mark.parametrize("value", [
    CPE23,
    CPE22,
    "cpe:/a:vendor:prod",
    r"cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*",  # escaped colon is data, not a separator
    "cpe:2.3:o:vendor:os:1.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:vendor:device:1.0:*:*:*:*:*:*:*",
    "cpe:2.3:*:vendor:prod:1.0:*:*:*:*:*:*:*",      # ANY, §6.2
    "cpe:2.3:-:vendor:prod:1.0:*:*:*:*:*:*:*",      # NA, §6.2
    "cpe:2.3:a:vendor:prod:1.0:*:*:en-US:*:*:*:*",  # language is an RFC 5646 tag
    "cpe:/A:vendor:prod",                           # §6.1 is case-insensitive
    "cpe:/",                                        # every component ANY
])
def test_cpe_wellformed_accepts(value):
    assert _check("cpe_wellformed", value)


@pytest.mark.parametrize("value", [
    "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*",       # 12 components, not 13
    "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*:*",   # 14
    "cpe:/x:vendor:prod",                          # part must be a, h or o
    "cpe:/a:1:2:3:4:5:6:7",                        # more than 7 components
    "cpe:2.3:x:vendor:prod:1.0:*:*:*:*:*:*:*",     # part must be a, h or o
    "cpe:2.3::vendor:prod:1.0:*:*:*:*:*:*:*",      # empty part is not ANY here; §6.2 spells that '*'
    "cpe:2.3:a:vendor:prod:1.0:::::::",            # 13 components, but empty ones: 2.2's convention
    "cpe:2.3:a::prod:1.0:*:*:*:*:*:*:*",           # one empty attribute is enough
    "cpe:2.3:a:vendor name:prod:1.0:*:*:*:*:*:*:*",  # a space must be escaped
    "cpe:/a:vendor name:prod",                       # likewise in the URI binding
    "cpe:2.3:a:vendor:prod:1.0:*:*:zz-QQ-XX:*:*:*:*",  # not an RFC 5646 tag
    PURL,
    "vendor:prod:1.0",
])
def test_cpe_wellformed_rejects(value):
    assert not _check("cpe_wellformed", value)


def _cpe23(*attributes):
    """A CPE 2.3 name from `part` plus the 10 attributes after it, padded with
    ANY. Built rather than typed: these names are 13 colon-separated components
    and hand-written ones are easy to get one short, which the count check would
    then reject for the wrong reason.
    """
    attrs = list(attributes) + ["*"] * (11 - len(attributes))
    return ":".join(["cpe", "2.3", *attrs])


def test_an_escaped_colon_is_data_not_a_delimiter():
    """§6.2.2: a backslash escapes the character after it."""
    name = _cpe23("a", r"ven\:dor", "prod", "1.0")
    assert _check("cpe_wellformed", name)


def test_a_colon_after_an_escaped_backslash_is_a_delimiter():
    """The parity case. `\\` is a literal backslash ending the attribute, so the
    colon after it separates components -- the run before it has even length.

    A one-character lookbehind read that colon as escaped and undercounted the
    components, failing a valid name. False FAIL is the wrong direction for a
    conformance tool: it reports a correct document as violating a requirement.
    """
    name = _cpe23("a", "ven" + "\\" * 2, "prod", "1.0")
    assert _check("cpe_wellformed", name)


def test_three_backslashes_escape_the_colon_again():
    """Odd run: the first two escape each other, the third escapes the colon."""
    name = _cpe23("a", "ven" + "\\" * 3 + ":dor", "prod", "1.0")
    assert _check("cpe_wellformed", name)


@pytest.mark.parametrize("raw,expected", [
    ("a:b:c", ["a", "b", "c"]),
    (r"a\:b:c", [r"a\:b", "c"]),          # odd run -> escaped, one component
    ("a" + "\\" * 2 + ":b", ["a" + "\\" * 2, "b"]),   # even run -> delimiter
    ("", [""]),
    (":", ["", ""]),
])
def test_split_unescaped_counts_backslash_runs_by_parity(raw, expected):
    assert _split_unescaped(raw) == expected


@pytest.mark.parametrize("value", [PURL, CPE23, CPE22])
def test_component_identifier_accepts_either_form(value):
    assert _check("component_identifier", value)


@pytest.mark.parametrize("value", ["not-an-identifier", "cpe:2.3:a:bad", "pkg:", "",
                                   "cpe:2.3:x:vendor:prod:1.0:*:*:*:*:*:*:*"])
def test_component_identifier_rejects_malformed(value):
    # An empty value is absence, which `present` reports; this validator only
    # judges the shape of values that are there.
    assert _check("component_identifier", value) == (value == "")


def test_the_grammar_is_checked_not_just_the_shape():
    """A component count and a `part` check are not the grammar.

    Structural checks passed malformed names one class at a time -- any part
    value, then empty attributes, then attribute text with spaces in it. The
    validator matches NIST IR 7695's own expressions so the whole class is
    closed rather than the last example someone thought of.
    """
    assert not _check("cpe_wellformed", "cpe:2.3:a:vendor name:prod:1.0:*:*:*:*:*:*:*")
    # A space is not escapable either: §6.2.2's escape set is punctuation, and a
    # space is not in it. `\ ` is as malformed as a bare one.
    assert not _check("cpe_wellformed", r"cpe:2.3:a:vendor\ name:prod:1.0:*:*:*:*:*:*:*")
    # What escaping is for: a special character that *is* in the set.
    assert _check("cpe_wellformed", r"cpe:2.3:a:vendor\!:prod:1.0:*:*:*:*:*:*:*")


def test_the_uri_binding_is_case_insensitive():
    """§6.1 writes the scheme and part case-insensitively. An a/h/o-only check
    rejected `cpe:/A:vendor:prod`, which is a valid name -- a false FAIL."""
    assert _check("cpe_wellformed", "cpe:/A:vendor:prod")
    assert _check("cpe_wellformed", "cpe:/a:vendor:prod")


def test_the_part_check_does_not_depend_on_the_binding():
    """The same product, named in both bindings, must get the same verdict.

    `part` was checked for the 2.2 URI and not for the 2.3 formatted string, so
    `cpe:/x:...` failed while `cpe:2.3:x:...` passed. A validator whose answer
    depends on which binding the document chose is reporting on the encoding, not
    on the identifier.
    """
    for bad_part in ("x", "z", "1"):
        assert not _check("cpe_wellformed", f"cpe:/{bad_part}:vendor:prod")
        assert not _check("cpe_wellformed",
                          f"cpe:2.3:{bad_part}:vendor:prod:1.0:*:*:*:*:*:*:*")
    for good_part in ("a", "h", "o"):
        assert _check("cpe_wellformed", f"cpe:/{good_part}:vendor:prod")
        assert _check("cpe_wellformed",
                      f"cpe:2.3:{good_part}:vendor:prod:1.0:*:*:*:*:*:*:*")


# ---- MUST_WHERE_AVAILABLE over container fields -------------------------------
# "Where available" excuses a document that never declared the data. Deciding
# availability with an inline `value is not None` counted an empty container as
# declared, so a component with no hashes at all reported FAIL -- exactly the
# case the severity exists to excuse. `cisa-component-hash` is such a rule.

def _hash_verdict(tmp_path, **component):
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z",
                     "tools": [{"name": "t", "version": "1"}]},
        "components": [{"type": "library", "name": "x", "version": "1.0",
                        "purl": "pkg:npm/x@1.0", **component}],
    }
    path = tmp_path / "hashes.cdx.json"
    path.write_text(json.dumps(doc))
    (result,) = run(str(path), ["cisa-2025-min"])
    return next(f.verdict.value for f in result.findings
                if f.rule_id == "cisa-component-hash")


def test_a_component_declaring_no_hash_is_not_a_violation(tmp_path):
    assert _hash_verdict(tmp_path) == "WARN"


def test_a_component_declaring_an_empty_hash_list_is_not_a_violation(tmp_path):
    assert _hash_verdict(tmp_path, hashes=[]) == "WARN"


def test_a_component_declaring_the_wrong_hash_still_fails(tmp_path):
    """The other half. Softening absence must not soften a hash that is there
    and does not meet the requirement."""
    assert _hash_verdict(
        tmp_path, hashes=[{"alg": "MD5", "content": "d41d8cd98f00b204e9800998ecf8427e"}]
    ) == "FAIL"


# ---- rule field resolution ---------------------------------------------------

def _rule(**kwargs):
    return Rule(id="r", scope="component", severity=None, category=None,
                validators=[], **kwargs)


def test_fields_takes_precedence_over_field():
    assert _rule(field="purl", fields=["cpe", "purl"]).lookup_fields() == ["cpe", "purl"]


def test_single_field_still_resolves():
    assert _rule(field="purl").lookup_fields() == ["purl"]


def test_a_rule_naming_no_field_resolves_to_nothing():
    assert _rule().lookup_fields() == []


class _Target:
    def __init__(self, purl=None, cpe=None):
        self.purl = purl
        self.cpe = cpe


def test_extract_any_returns_the_first_field_carrying_a_value():
    assert _extract_any(_Target(purl=PURL, cpe=CPE23), ["purl", "cpe"]) == PURL


def test_extract_any_falls_through_to_the_later_field():
    assert _extract_any(_Target(cpe=CPE23), ["purl", "cpe"]) == CPE23


def test_extract_any_skips_null_tokens():
    """NOASSERTION is SPDX for "no value", so it must not shadow a real one."""
    assert _extract_any(_Target(purl="NOASSERTION", cpe=CPE23), ["purl", "cpe"]) == CPE23


def test_extract_any_treats_an_empty_container_as_absent():
    """Not every IR field is a string. `licenses` and `hashes` are containers, and
    an empty one is absence -- which is how `present` reads it. Returning it as
    though it carried data would let it shadow a populated alternative behind it,
    and the rule would then report absence while a listed field was satisfied.
    """
    target = SimpleNamespace(licenses=[], purl=PURL)
    assert _extract_any(target, ["licenses", "purl"]) == PURL


def test_extract_any_treats_an_all_null_container_as_absent():
    target = SimpleNamespace(licenses=["NOASSERTION"], purl=PURL)
    assert _extract_any(target, ["licenses", "purl"]) == PURL


def test_extract_any_keeps_a_populated_container():
    target = SimpleNamespace(licenses=["MIT"], purl=PURL)
    assert _extract_any(target, ["licenses", "purl"]) == ["MIT"]


def test_extract_any_reports_absence_when_nothing_is_set():
    assert _extract_any(_Target(), ["purl", "cpe"]) is None
