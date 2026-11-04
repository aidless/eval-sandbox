import pytest


@pytest.fixture()
def workdir(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    return str(d)


@pytest.fixture()
def forbidden_path(tmp_path):
    d = tmp_path / "host_only"
    d.mkdir()
    p = d / "secret.txt"
    p.write_text("host-only\n", encoding="utf-8")
    return str(p)
