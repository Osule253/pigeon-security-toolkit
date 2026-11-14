# Pigeon Security Toolkit (PST)

**Secure. Inspect. Defend.**

Pigeon Security Toolkit (PST) is an open-source Python command-line security inspection toolkit developed by **Pigeon Techies**.

Website: https://pigeontechies.com

## Features

- SHA-256 file hashing
- DNS inspection
- Website security-header auditing
- SSL/TLS certificate inspection
- Authorized TCP port scanning
- Scan history and comparison
- Unified security assessment
- JSON and HTML reports

## Requirements

- Python 3.11 or later
- Internet connection for remote DNS, website and SSL/TLS inspections
- No third-party Python packages currently required

## Installation from source

Clone the repository:

```bash
git clone https://github.com/Osule253/pigeon-security-toolkit.git
cd pigeon-security-toolkit
```

## Usage

Display the version and help:

```bash
python pst.py --version
python pst.py --help
```

Examples:

```bash
python pst.py hash example.txt
python pst.py dns example.com
python pst.py audit https://example.com
python pst.py ssl example.com
python pst.py scan example.com --authorized
python pst.py history
python pst.py assess example.com --authorized
```

For port-scanning options:

```bash
python pst.py scan --help
```

## Supported platforms

- Android through Termux
- Linux
- Windows

Installation scripts for these platforms are being developed.

## Automated testing

Run the local test suite:

```bash
python -m py_compile pst.py pigeon_portscan.py pigeon_history.py
python -m unittest discover -s tests -v
```

GitHub Actions is configured to test supported Python versions on Linux and Windows.

## Responsible use

PST is a defensive security inspection tool. Its findings are indicators, not proof that a system is secure or vulnerable.

Only scan or assess systems you own or have explicit permission to test.

## Contributions

Contributions, bug reports and feature suggestions are welcome.

## Licence

MIT License. See [LICENSE](LICENSE).

---

Developed by **Pigeon Techies**

https://pigeontechies.com

**PIGEON SECURITY TOOLKIT — SECURE. INSPECT. DEFEND.**
