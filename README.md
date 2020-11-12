<!-- cargo-sync-readme start -->

# ntp-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/ntp-parser.svg?branch=master)](https://travis-ci.org/rusticata/ntp-parser)
[![Crates.io Version](https://img.shields.io/crates/v/ntp-parser.svg)](https://crates.io/crates/ntp-parser)

## Overview

ntp-parser is a parser for the NTP protocol.

This crate mostly serves as a demo/example crate for network protocol parsers written using nom, and nom-derive.
<!-- cargo-sync-readme end -->

## Changes

### 0.5.0

- Upgrade to nom 6
- Convert all macro-based parsers to functions
- Convert to nom-derive

### 0.4.0

- Set edition to 2018
- Upgrade to nom 5

### 0.3.0

- Upgrade to nom 4

### 0.2.1

- Fix parsing of extensions

### 0.2.0

- Use newtype for NtpMode, remove enum_primitive
- Switch license to MIT + APLv2

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
