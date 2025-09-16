//! # ntp-parser
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
