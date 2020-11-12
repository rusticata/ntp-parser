//! # ntp-parser
//!
//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Build Status](https://travis-ci.org/rusticata/ntp-parser.svg?branch=master)](https://travis-ci.org/rusticata/ntp-parser)
//! [![Crates.io Version](https://img.shields.io/crates/v/ntp-parser.svg)](https://crates.io/crates/ntp-parser)
//!
//! ## Overview
//!
//! ntp-parser is a parser for the NTP protocol.
//!
//! This crate mostly serves as a demo/example crate for network protocol parsers written using nom, and nom-derive.

// add missing_docs
#![deny(
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

pub use ntp::*;
pub mod ntp;
