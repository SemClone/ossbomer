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


def test_the_guide_does_not_describe_a_profile_as_something_it_is_not():
    """Listing the id is not enough. The catalog said `fedramp-sbom` was
    "FedRAMP SBOM requirements" while the profile had been renamed precisely
    because FedRAMP publishes no SBOM requirements, so the table asserted the
    claim the code had stopped making.

    Checks the first significant word of the profile's own name appears in its
    row. Loose on purpose: the guide labels a standard, not the profile, so
    they will not match verbatim.
    """
    rows = {}
    for line in (DOCS / "guide" / "profiles.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("| `") and "|" in line[3:]:
            pid = line.split("`")[1]
            rows[pid] = line

    for pid in list_catalog():
        profile = load_profile(pid)
        if profile.withdrawn or pid not in rows:
            continue
        # The word that carries the claim: the standard or body being encoded.
        head = profile.name.split("(")[0].split(",")[0].strip()
        first = head.split()[0]
        assert first.lower() in rows[pid].lower(), (
            f"{pid} is described as {rows[pid].split('|')[2].strip()!r} "
            f"but the profile calls itself {profile.name!r}")


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
