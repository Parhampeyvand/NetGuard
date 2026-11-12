# NetGuard — Network Monitoring CLI

**[فارسی / Persian README](README_FA.md) | English**

#### Description

NetGuard is a Python command-line tool created as a CS50P final project. It
checks a small, user-selected set of TCP ports on a **private IPv4 or loopback
address**, saves the observation to JSON, and compares two reports to identify
changes. NetGuard is meant for basic monitoring of devices and services that
you own or are explicitly authorized to check. It is not a vulnerability
scanner, network discovery engine, or intrusion detection system.

The motivating problem is straightforward: after changing a router, launching a
local web app, or restarting a server, it is useful to know which TCP endpoints
accepted connections. A single observation provides limited context. Saving
reports makes it possible to compare a later scan with an earlier one, helping
users notice that a service has become reachable or stopped accepting
connections. The program deliberately avoids overstating its results: a failed
TCP connection can mean a closed port, a firewall, an offline host, or a
network error. Therefore, the output uses **`no_connection`** rather than
claiming a port is definitely closed.

## Requirements

- Python 3.11 or newer (the application itself uses the standard library only)
- `pytest` for unit tests (listed in `requirements.txt`)
- No administrative privileges are required for ordinary TCP connect checks

## Installation

```bash
python -m pip install -r requirements.txt
```

## Usage

### Interactive mode

```bash
python project.py
```

Choose **1** to check ports, **2** to compare saved reports, or **3** to exit.
Enter an authorized private/loopback IPv4 target and a comma-separated list of
ports, such as `22,80,443`. If left blank, the port list defaults to those
three common ports. Scan results are saved automatically under `reports/`.

### Command-line mode

```bash
python project.py --help
python project.py scan --host 127.0.0.1 --ports 22,80,443
python project.py scan --host 192.168.1.10 --ports 22,443 --output reports/server-before.json
python project.py scan --host 192.168.1.10 --ports 22,443 --output reports/server-after.json
python project.py compare --before reports/server-before.json --after reports/server-after.json
```

The above addresses are **examples**, not claims about any real device. A
Codespace's `127.0.0.1` is the Codespace itself, **not your personal laptop**.
You may scan up to 20 distinct TCP ports per run; each connection has a short
timeout. Only `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `127.0.0.0/8`
IPv4 targets are accepted. Public IPs, DNS names, IPv6, and broad subnet sweeps
are intentionally unsupported.

## Files

- **`project.py`**: application entry point (`main`) and functions for IP
  validation, port parsing, TCP connection checks, scanning, JSON storage, and
  report comparisons.
- **`test_project.py`**: pytest suite that tests the main helper functions,
  error cases, save/load round trips, and CLI behavior. Network checks are
  mocked during testing, so the tests make no real scan connections.
- **`requirements.txt`**: test dependency declaration; runtime uses Python's
  standard library.
- **`README.md`**: project overview, design choices, and usage instructions.
- **`.github/workflows/tests.yml`**: optional GitHub Actions workflow running
  pytest on three Python versions.
- **`.gitignore`**: excludes generated reports, local environments, and caches.
- **`LICENSE`**: MIT open-source license.

## Design decisions

I chose the standard-library `socket` module instead of a full network scanning
framework. TCP connect checks are understandable for a beginner and can be
unit-tested by injecting a fake checker or monkeypatching socket connections.
`validate_host` uses `ipaddress` and an explicit list of private/loopback
networks to limit the scope. `parse_ports` validates every number and limits
scans to 20 ports, making mistakes less likely. `scan_target` produces a small
structured dictionary, while `save_report` persists it as readable JSON.

`compare_reports` only compares **overlapping port numbers** from reports for
the same target. Ports tested on just one occasion are reported separately
rather than treated as opened or closed. This avoids false change alerts when
the user chooses different ports across scans.

The program is intentionally a command-line application because CS50P focuses
on Python logic rather than graphical front ends. A future version could add
scheduled scans, a graphical interface, or notifications after a user-reviewed
baseline. Any future monitoring should retain permission-based scope limits.

## Testing

```bash
python -m pytest -v test_project.py
```

The tests cover valid and invalid host addresses, port lists, TCP connection
success/failure (using mocks), changes between saved reports, file round trips,
and CLI error handling. The test suite should run without internet access.

## Privacy and safety

Run NetGuard only on systems you own or have permission to examine. Report
files may contain network addresses and port information; review them before
sharing or committing them to GitHub. The `reports/` directory is ignored by
Git. NetGuard does not collect passwords or perform authentication attempts.

## CS50P final-project submission

Keep `project.py`, `test_project.py`, `requirements.txt`, and this `README.md`
in the project root. Replace the placeholder video-demo URL above with your
actual public or unlisted demo link, verify the project meets the current
CS50P requirements, and submit from the project directory as directed by CS50.
