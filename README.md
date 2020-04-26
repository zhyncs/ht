# ht

[![Build Status][build-actions-svg]][build-actions]
[![Lint Status][lint-actions-svg]][lint-actions]
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Contributions](https://img.shields.io/badge/contributions-welcome-green.svg)](https://github.com/zhyncs/ht)

[build-actions-svg]: https://github.com/zhyncs/ht/workflows/Build/badge.svg?branch=master&event=push
[build-actions]: https://github.com/zhyncs/ht/actions?query=workflow%3ABuild+branch%3Amaster+event%3Apush
[lint-actions-svg]: https://github.com/zhyncs/ht/workflows/Lint/badge.svg?branch=master&event=push
[lint-actions]: https://github.com/zhyncs/ht/actions?query=workflow%3ALint+branch%3Amaster+event%3Apush

ht is an encrypted proxy server compatible with ss. It supports single user, TCP and IPv4. It uses port `443` and method `aes-128-gcm`.

## Prerequisite

```bash
sudo apt install -y libssl-dev
```

## Installation

```bash
mkdir build && cd build && cmake .. && make
```

## Usage

```bash
ht -k <password>
```

## References

- [SOCKS5 RFC](https://tools.ietf.org/html/rfc1928)

- [DNS RFC](https://tools.ietf.org/html/rfc1035)

- [Protocol](https://shadowsocks.org/en/spec/Protocol.html)

- [AEAD Ciphers](https://shadowsocks.org/en/spec/AEAD-Ciphers.html)
