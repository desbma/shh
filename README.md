# SHH (Systemd Hardening Helper)

[![Build status](https://github.com/desbma/shh/actions/workflows/ci.yml/badge.svg)](https://github.com/desbma/shh/actions)
[![AUR version](https://img.shields.io/aur/version/shh.svg?style=flat)](https://aur.archlinux.org/packages/shh/)
[![License](https://img.shields.io/github/license/desbma/shh.svg?style=flat)](https://github.com/desbma/shh/blob/master/LICENSE)

Automatic [systemd](https://systemd.io/) service hardening guided by [strace](https://strace.io/) profiling.

See [this article](https://www.synacktiv.com/publications/systemd-hardening-made-easy-with-shh) for an introduction.

[Official repository](https://github.com/desbma/shh) - [Mirror repository](https://github.com/synacktiv/shh)

## Installation

### Dependencies

Strace needs to be installed and available in the path. Strace version >=6.4 is strongly recommended.

### From source

You need a Rust build environment for example from [rustup](https://rustup.rs/).

```
cargo build --release
install -Dm 755 -t /usr/local/bin target/release/shh
```

### Debian

See [GitHub releases](https://github.com/desbma/shh/releases) for Debian packages built for each tagged version.

### Arch Linux

Arch Linux users can install the [shh AUR package](https://aur.archlinux.org/packages/shh).

## Usage

To harden a system unit named `SERVICE.service`:

1. Start service profiling: `shh service start-profile SERVICE`. The service will be restarted with strace profiling.
2. Use the service normally for a while, trying to cover as much features and use cases as possible.
3. Run `shh service finish-profile SERVICE -a`. The service will be restarted with a hardened configuration built from previous runtime profiling, to allow it to run safely as was observed during the profiling period, and to deny other dangerous system actions.

Run `shh -h` for full command line reference, or append `-h` to a subcommand to get help.

Services running in per-user instances of the service manager (controlled via `systemctl --user ...`) are **not** supported.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0-standalone.html)
