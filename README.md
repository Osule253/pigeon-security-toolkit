# Pigeon Security Toolkit (PST)

**Secure. Inspect. Defend.**

Pigeon Security Toolkit is an open-source Python command-line security
inspection toolkit developed by Pigeon Techies.

Website: https://pigeontechies.com

## Features

- SHA-256 file hashing
- DNS inspection
- Website security-header auditing
- SSL/TLS certificate inspection
- Authorized TCP port scanning
- Scan history and comparison
- Unified security assessment

## Requirements

- Python 3.10 or later (initial target; compatibility testing pending)
- Internet connection for remote DNS, website and SSL inspections

The core application currently uses Python standard-library modules.

## Run from source

```bash
python pst.py --help
python pst.py --version
python pst.py hash example.txt
python pst.py dns example.com
python pst.py ssl example.com
python pst.py audit https://example.com
cat README.md
> ```
>
> For port scanning and unified assessments, only test systems you own
> or have explicit permission to assess.
>
> ## Supported Platforms
>
> - Android through Termux
> - Linux
> - Windows
>
> ## Licence
>
> MIT License. See [LICENSE](LICENSE).
>
> ## Contributions
>
> Contributions, bug reports and feature suggestions are welcome.
>
> ## Responsible Use
>
> PST is a defensive security inspection tool. Its findings are indicators,
> not proof that a system is secure or vulnerable.
>
> Only assess systems you own or have explicit permission to test.
>
> ---
>
> Developed by **Pigeon Techies**
>
> https://pigeontechies.com
>
> **PIGEON SECURITY TOOLKIT — SECURE. INSPECT. DEFEND.**
> EOF
cat README.md
