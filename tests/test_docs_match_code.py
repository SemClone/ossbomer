"""The documentation must not drift from the code.

The validator table in the CLI reference went stale once already: it listed
fourteen while eighteen shipped, so four validators added in 2.1.0 were
undiscoverable for anyone reading the docs rather than running the command.
"""
import pathlib
import re

from ossbomer.core import validators as V
from ossbomer.core.profile import list_catalog, load_profile

DOCS = pathlib.Path(__file__).parent.parent / "docs"


def test_every_validator_appears_in_the_cli_reference():
    documented = set(re.findall(r"^\| `([a-z0-9_]+)` \|",
                                (DOCS / "reference" / "cli.md").read_text(encoding="utf-8"),
                                re.MULTILINE))
    # Leading underscore marks a private validator, which tests register and
    # plugins may too. Only the public set is a documentation promise.
    public = {v for v in V.available() if not v.startswith("_")}
    missing = public - documented
    assert not missing, f"undocumented validators: {sorted(missing)}"


def test_the_reference_does_not_document_validators_that_do_not_exist():
    documented = set(re.findall(r"^\| `([a-z0-9_]+)` \|",
                                (DOCS / "reference" / "cli.md").read_text(encoding="utf-8"),
                                re.MULTILINE))
    # The table also carries non-validator rows; only check names that look like
    # validators and are not registered.
    stale = {d for d in documented if d.endswith(("_wellformed", "_normalized"))
             or d in {"present", "declared", "non_placeholder"}} - set(V.available())
    assert not stale, f"documented but not registered: {sorted(stale)}"


def test_every_usable_profile_is_listed_in_the_guide():
    listed = (DOCS / "guide" / "profiles.md").read_text(encoding="utf-8")
    for pid in list_catalog():
        assert f"`{pid}`" in listed, f"{pid} is not in the profiles guide"


def test_withdrawn_profiles_are_marked_as_such_in_the_guide():
    listed = (DOCS / "guide" / "profiles.md").read_text(encoding="utf-8")
    for pid in list_catalog():
        if load_profile(pid).withdrawn:
            row = next(ln for ln in listed.splitlines() if f"`{pid}`" in ln)
            assert "ithdrawn" in row, f"{pid} is listed without saying it is withdrawn"


def test_documented_environment_variables_exist_in_code():
    from ossbomer.core.licenses import ENV_ALIASES
    from ossbomer.core.profile import ENV_PATH

    reference = (DOCS / "reference" / "profile-format.md").read_text(encoding="utf-8")
    for var in (ENV_PATH, ENV_ALIASES):
        assert var in reference, f"{var} is not documented"
