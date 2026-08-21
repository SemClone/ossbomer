"""A profile's filename and its `id` are one identity, and must agree.

`_resolve_path` finds a profile by filename; everything afterwards reports the
`id` inside it. Nothing checked the two matched, so a file named
`my-policy.yaml` declaring `id: acme-baseline` loaded under `--profile
my-policy` and reported `acme-baseline` in every finding, JSON report and SARIF
run. Grepping CI output for the name that was invoked found nothing.

`extends` resolves by filename while `excludes` targets the id, so composition
saw the same split.

Every bundled profile is named after its id, which is why the catalog never
exercised this and no test would have caught a regression. It was adopters
writing private overlays -- a documented, supported workflow -- who paid for it.
"""
import pytest

from ossbomer.core.profile import ProfileError, list_catalog, load_profile

GOOD = """\
id: {id}
name: Test
version: "1"
sources: [{{name: t, ref: t, url: "https://example.com"}}]
rules:
  - id: r1
    scope: document
    severity: MUST
    category: Completeness
    citation: c
    field: timestamp
    validators: [present]
"""


def _write(tmp_path, filename, profile_id):
    path = tmp_path / filename
    path.write_text(GOOD.format(id=profile_id))
    return path


def test_a_matching_id_and_filename_loads(tmp_path):
    _write(tmp_path, "acme-baseline.yaml", "acme-baseline")
    assert load_profile("acme-baseline", [str(tmp_path)]).id == "acme-baseline"


def test_the_yml_extension_is_still_accepted(tmp_path):
    """Both spellings resolve, so the check compares the stem rather than
    assuming `.yaml`."""
    _write(tmp_path, "acme-baseline.yml", "acme-baseline")
    assert load_profile("acme-baseline", [str(tmp_path)]).id == "acme-baseline"


def test_a_direct_path_still_loads(tmp_path):
    """A path is a supported way to name a profile, and its file still has to
    agree with what it declares."""
    path = _write(tmp_path, "acme-baseline.yaml", "acme-baseline")
    assert load_profile(str(path)).id == "acme-baseline"


def test_a_mismatched_id_is_refused(tmp_path):
    """The defect: this loaded happily and reported the other name throughout."""
    _write(tmp_path, "my-policy.yaml", "acme-baseline")
    with pytest.raises(ProfileError, match="resolved by filename"):
        load_profile("my-policy", [str(tmp_path)])


def test_the_mismatch_message_names_both_and_both_fixes(tmp_path):
    """Whoever hits this has to know which of the two to change, and either is
    valid. A message naming only one of them is half an answer."""
    _write(tmp_path, "my-policy.yaml", "acme-baseline")
    with pytest.raises(ProfileError) as excinfo:
        load_profile("my-policy", [str(tmp_path)])
    message = str(excinfo.value)
    assert "acme-baseline" in message and "my-policy" in message
    assert "acme-baseline.yaml" in message


def test_a_mismatch_by_path_is_refused_too(tmp_path):
    """Naming the file directly does not make the two identities agree."""
    path = _write(tmp_path, "my-policy.yaml", "acme-baseline")
    with pytest.raises(ProfileError, match="resolved by filename"):
        load_profile(str(path))


def test_the_not_found_message_says_what_it_looked_for(tmp_path):
    """"Not found" sent readers hunting for a missing file when the file was
    right there under another name -- the likeliest cause, and the one the
    message never mentioned."""
    _write(tmp_path, "f.yaml", "acme-baseline")
    with pytest.raises(ProfileError) as excinfo:
        load_profile("acme-baseline", [str(tmp_path)])
    message = str(excinfo.value)
    assert "acme-baseline.yaml" in message
    assert "resolve by filename" in message
    assert str(tmp_path) in message


def test_composition_cannot_straddle_the_two_names(tmp_path):
    """`extends` resolves by filename while `excludes` targets the id. With the
    two free to differ, a profile could extend one name and be excluded under
    another."""
    _write(tmp_path, "base.yaml", "not-base")
    (tmp_path / "child.yaml").write_text(
        'id: child\nname: C\nversion: "1"\n'
        'sources: [{name: t, ref: t, url: "https://example.com"}]\n'
        "extends: [base]\n")
    with pytest.raises(ProfileError, match="resolved by filename"):
        load_profile("child", [str(tmp_path)])


@pytest.mark.parametrize("pid", sorted(list_catalog()))
def test_every_bundled_profile_already_agrees(pid):
    """This must cost the catalog nothing. If a bundled profile ever fails here
    it is the profile that is wrong, not the check."""
    assert load_profile(pid).id == pid

def test_the_filename_rule_does_not_depend_on_the_filesystem(tmp_path):
    """macOS and Windows are case-insensitive; Linux is not.

    `os.path.isfile` answers the filesystem's question rather than ours, so
    `Acme-Baseline.yaml` was found by `--profile acme-baseline` on a laptop and
    not found in CI -- the same overlay giving two answers depending on where it
    ran, which is the class of bug this project keeps having to close.

    Refused everywhere now. On a case-sensitive filesystem this was already the
    behaviour, so the test passes there for the original reason.
    """
    _write(tmp_path, "Acme-Baseline.yaml", "acme-baseline")
    with pytest.raises(ProfileError, match="Profile not found"):
        load_profile("acme-baseline", [str(tmp_path)])


def test_the_exact_spelling_still_resolves(tmp_path):
    """The check must not refuse the name it was given correctly."""
    _write(tmp_path, "Acme-Baseline.yaml", "Acme-Baseline")
    assert load_profile("Acme-Baseline", [str(tmp_path)]).id == "Acme-Baseline"


def test_an_unreadable_directory_does_not_refuse_a_real_profile(tmp_path, monkeypatch):
    """Listing the directory is how the spelling is confirmed. If that fails for
    a reason unrelated to the profile -- permissions, a racing unlink -- fall
    back to what the filesystem said rather than refusing a file that is there.
    """
    _write(tmp_path, "acme-baseline.yaml", "acme-baseline")

    def boom(_):
        raise PermissionError("nope")

    monkeypatch.setattr("ossbomer.core.profile.os.listdir", boom)
    assert load_profile("acme-baseline", [str(tmp_path)]).id == "acme-baseline"
