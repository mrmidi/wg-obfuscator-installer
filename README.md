# wg-obfuscator-installer

Installer for wg-obfuscator and WireGuard on Debian/Ubuntu systems.

What this repository contains

- `install-wg+wgo.sh` — installer script that builds/installs `wg-obfuscator`, configures WireGuard, and manages nftables rules for a loopback-only WireGuard instance. (Alternative Bash implementation; the Python version in `wg_installer/` is recommended for new installations.)
- `wg_installer/` — Python package providing a CLI and optional TUI for installation, with internationalization support.

Quick usage

Run a dry-run first to verify what will change:

```bash
sudo bash install-wg+wgo.sh --dry-run
```

To perform installation interactively:

```bash
sudo bash install-wg+wgo.sh
```

To uninstall (safe remove, keeps configs/keys):

```bash
sudo bash install-wg+wgo.sh --uninstall
```

To purge all installed files including keys and state:

```bash
sudo bash install-wg+wgo.sh --purge
```

Notes

- The installer prefers `nftables` and will apply rules transactionally at runtime and persist them under `/etc/nftables.d/`.
- The public obfuscator port defaults to `3478` and the internal WireGuard port defaults to `51820`. These can be overridden with environment variables `PUB_PORT` and `WG_PORT`.
- The script has a `--dry-run` mode which prints actions instead of making changes.

License

This repository is provided as-is; adapt as necessary for your environment.
