from runtime_sensor.redact import REDACTED, safe_cmdline


def test_key_value_args():
    out = safe_cmdline(["app", "--db-password=hunter2", "API_KEY=abc", "mode=fast"])
    assert "hunter2" not in out and "abc" not in out
    assert "mode=fast" in out
    assert f"--db-password={REDACTED}" in out


def test_flag_followed_by_value():
    out = safe_cmdline(["vault", "login", "--token", "s.ABCDEF", "-v"])
    assert "s.ABCDEF" not in out and out.endswith("-v")


def test_url_credentials_and_bearer():
    out = safe_cmdline(["git", "clone", "https://bob:sup3rs3cret@github.com/x/y.git"])
    assert "sup3rs3cret" not in out and "bob:" in out and "@github.com" in out
    out = safe_cmdline(["curl", "-H", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"])
    assert "eyJhbGci" not in out


def test_known_token_shapes():
    out = safe_cmdline(["aws", "AKIAABCDEFGHIJKLMNOP", "ghp_" + "a" * 36])
    assert "AKIA" not in out and "ghp_" not in out


def test_mysql_p_flag():
    assert "secret" not in safe_cmdline(["mysql", "-uroot", "-psecret", "db"])
    assert safe_cmdline(["grep", "-pattern"]) == "grep -pattern"  # -p only redacted for db clients


def test_truncation():
    out = safe_cmdline(["x"] + ["a" * 100] * 50, max_len=200)
    assert len(out) == 200 and out.endswith("...")


def test_plain_command_untouched():
    assert safe_cmdline(["ls", "-la", "/tmp"]) == "ls -la /tmp"
