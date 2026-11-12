"""Unit tests for NetGuard's CS50P project.py."""

import json
import socket

import pytest

from project import (
    check_port,
    compare_reports,
    load_report,
    main,
    parse_ports,
    save_report,
    scan_target,
    validate_host,
)


def sample_report(target="192.168.1.10", entries=None):
    return {
        "application": "NetGuard",
        "version": "1.0.0",
        "timestamp_utc": "2026-01-01T00:00:00+00:00",
        "target": target,
        "results": entries if entries is not None else [],
    }


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.2", "172.16.1.1", "192.168.1.25"])
def test_validate_host_accepts_allowed_addresses(host):
    assert validate_host(host) == host


@pytest.mark.parametrize("host", ["8.8.8.8", "169.254.1.2", "256.1.2.3", "localhost", "::1", "224.0.0.1"])
def test_validate_host_rejects_other_addresses(host):
    with pytest.raises(ValueError):
        validate_host(host)


def test_parse_ports_preserves_order_and_removes_duplicates():
    assert parse_ports("443, 22,80,443") == [443, 22, 80]


@pytest.mark.parametrize("text", ["", "22,", "0", "65536", "-1", "80.5", "abc", "1,,2"])
def test_parse_ports_rejects_invalid_input(text):
    with pytest.raises(ValueError):
        parse_ports(text)


def test_parse_ports_enforces_limit():
    with pytest.raises(ValueError):
        parse_ports(",".join(str(n) for n in range(1, 22)))


def test_check_port_connected(monkeypatch):
    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: FakeConnection())
    assert check_port("127.0.0.1", 80) is True


def test_check_port_failure(monkeypatch):
    def failed(*args, **kwargs):
        raise ConnectionRefusedError("simulated")

    monkeypatch.setattr(socket, "create_connection", failed)
    assert check_port("127.0.0.1", 80) is False


def test_scan_target_does_not_require_network():
    seen = []

    def fake_checker(host, port):
        seen.append((host, port))
        return port == 443

    report = scan_target("192.168.1.10", [22, 443], checker=fake_checker)
    assert report["target"] == "192.168.1.10"
    assert seen == [("192.168.1.10", 22), ("192.168.1.10", 443)]
    assert report["results"] == [
        {"port": 22, "status": "no_connection"},
        {"port": 443, "status": "open"},
    ]


def test_scan_rejects_public_address_without_probing():
    with pytest.raises(ValueError):
        scan_target("8.8.8.8", [80], checker=lambda host, port: pytest.fail("Should not probe"))


def test_compare_reports_reports_changes():
    before = sample_report(entries=[
        {"port": 22, "status": "open"},
        {"port": 80, "status": "no_connection"},
        {"port": 443, "status": "open"},
        {"port": 8080, "status": "open"},
    ])
    after = sample_report(entries=[
        {"port": 22, "status": "no_connection"},
        {"port": 80, "status": "open"},
        {"port": 443, "status": "open"},
        {"port": 3000, "status": "open"},
    ])
    result = compare_reports(before, after)
    assert result["newly_open"] == [80]
    assert result["no_longer_connectable"] == [22]
    assert result["unchanged"] == [443]
    assert result["only_in_before"] == [8080]
    assert result["only_in_after"] == [3000]


def test_compare_reports_rejects_different_hosts():
    with pytest.raises(ValueError):
        compare_reports(sample_report(), sample_report(target="192.168.1.11"))


def test_compare_reports_rejects_bad_status():
    with pytest.raises(ValueError):
        compare_reports(sample_report(entries=[{"port": 80, "status": "unknown"}]), sample_report())


def test_save_and_load_report(tmp_path):
    report = sample_report(entries=[{"port": 443, "status": "open"}])
    path = save_report(report, tmp_path / "nested" / "scan.json")
    assert path.exists()
    assert load_report(path) == report
    assert json.loads(path.read_text(encoding="utf-8")) == report


def test_load_report_rejects_other_json(tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text('{"application": "other"}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_report(path)


def test_main_cli_scan(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("project.check_port", lambda host, port, timeout=0.5: port == 443)
    path = tmp_path / "result.json"
    main(["scan", "--host", "127.0.0.1", "--ports", "80,443", "--output", str(path)])
    output = capsys.readouterr().out
    assert "open" in output
    assert load_report(path)["results"][1]["status"] == "open"


def test_main_cli_rejects_public_ip(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--host", "8.8.8.8", "--output", str(tmp_path / "out.json")])
    assert exc.value.code == 1
    assert not (tmp_path / "out.json").exists()
