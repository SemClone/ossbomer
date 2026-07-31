"""IR helpers."""
from ossbomer.core.ir import Component

# ---- Component.identity ------------------------------------------------------
# Used to label issue locations in reports (engine.py) and to name orphaned
# components (validators.py), so it has to degrade sensibly when a document is
# missing the fields it would normally key on.

def test_identity_prefers_purl():
    c = Component(purl="pkg:npm/left-pad@1.3.0", cpe="cpe:/a:x", name="left-pad",
                  version="1.3.0", bom_ref="ref-1")
    assert c.identity == "pkg:npm/left-pad@1.3.0"


def test_identity_falls_back_to_cpe():
    c = Component(cpe="cpe:/a:vendor:product:1.0", name="p", version="1.0")
    assert c.identity == "cpe:/a:vendor:product:1.0"


def test_identity_falls_back_to_name_and_version():
    c = Component(name="left-pad", version="1.3.0", bom_ref="ref-1")
    assert c.identity == "left-pad@1.3.0"


def test_identity_omits_a_missing_version():
    c = Component(name="left-pad")
    assert c.identity == "left-pad"


def test_identity_falls_back_to_bom_ref_when_unnamed():
    """The interesting case: no purl, no cpe, no name -- but a bom-ref exists."""
    c = Component(bom_ref="ref-1")
    assert c.identity == "ref-1"


def test_identity_falls_back_to_unknown():
    assert Component().identity == "<unknown>"
