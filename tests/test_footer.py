"""The CLI --markdown report footer: a short, price-free 'Work with me' pointer, suppressible via env.
With a prober it opens by naming the most severe control-risk class the report found."""
import types

from ownerwatch import cli


def _prober(*note_lists):
    """A minimal stand-in: _footer only reads prober.seen.values()[].notes."""
    seen = {str(i): types.SimpleNamespace(notes=list(ns)) for i, ns in enumerate(note_lists)}
    return types.SimpleNamespace(seen=seen)


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
    assert cli._footer(_prober(["owner() is an EOA 0xabc: no timelock or multisig on-chain"])) == ""


def test_footer_generic_when_no_critical_finding(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    # a short-but-present timelock is not a critical class -> the generic pointer, no risk-class lead
    f = cli._footer(_prober(["timelock delay is only 2h"]))
    assert f == cli.FOOTER
    assert "This report found" not in f


def test_footer_names_eoa(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    f = cli._footer(_prober(["owner() and upgrade admin is an EOA 0xabc: no timelock or multisig on-chain"]))
    assert "externally-owned key" in f
    assert "Work with me" in f and "github.com/imal1ice/ownerwatch" in f and "$" not in f


def test_footer_names_no_delay(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    assert "no enforced timelock" in cli._footer(_prober(["timelock delay is 0"]))


def test_footer_names_one_of_n(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    assert "single signer" in cli._footer(_prober(["DEFAULT_ADMIN_ROLE held by 1-of-N Safe 0xabc"]))


def test_footer_severity_priority_eoa_over_safe(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    f = cli._footer(_prober(["owner() is a 1-of-N Safe 0xabc"], ["admin is an EOA 0xdef: no timelock or multisig on-chain"]))
    assert "externally-owned key" in f  # EOA outranks 1-of-N
    assert "single signer" not in f


def test_footer_excludes_accessmanager_notes(monkeypatch):
    monkeypatch.delenv(cli.NO_FOOTER_ENV, raising=False)
    # AccessManager notes are repeated per target and excluded from the Findings section; the footer excludes them too
    f = cli._footer(_prober(["AccessManager 0x123: role 0 held by EOA 0xabc"]))
    assert f == cli.FOOTER
