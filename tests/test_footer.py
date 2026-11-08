"""The CLI --markdown report footer: a short, price-free 'Work with me' pointer, suppressible via env."""
from ownerwatch import cli


def test_footer_present_and_price_free(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    f = cli._footer()
    assert f.startswith("\n\n---\n")
    assert "Work with me" in f
    assert "github.com/imal1ice/ownerwatch" in f
    assert "$" not in f  # no price in outreach


def test_footer_suppressible(monkeypatch):
    monkeypatch.setenv(cli.NO_FOOTER_ENV, "1")
    assert cli._footer() == ""
