use nom::bytes::streaming::take;
use nom::combinator::{complete, map, map_parser, opt};
use nom::error::{make_error, ErrorKind};
use nom::multi::many1;
use nom::number::streaming::be_u8;
pub use nom::{Err, IResult};
use nom_derive::*;

#[derive(Debug, PartialEq)]
pub enum NtpPacket<'a> {
    V3(NtpV3Packet<'a>),
    V4(NtpV4Packet<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, NomBE)]
pub struct NtpMode(pub u8);

#[allow(non_upper_case_globals)]
impl NtpMode {
    pub const Reserved: NtpMode = NtpMode(0);
    pub const SymmetricActive: NtpMode = NtpMode(1);
    pub const SymmetricPassive: NtpMode = NtpMode(2);
    pub const Client: NtpMode = NtpMode(3);
    pub const Server: NtpMode = NtpMode(4);
    pub const Broadcast: NtpMode = NtpMode(5);
    pub const NtpControlMessage: NtpMode = NtpMode(6);
    pub const Private: NtpMode = NtpMode(7);
}

/// An NTP version 3 packet
#[derive(Debug, PartialEq, NomBE)]
pub struct NtpV3Packet<'a> {
    #[nom(PreExec = "let (i, b0) = be_u8(i)?;")]
    #[nom(Value(b0 >> 6))]
    pub li: u8,
    #[nom(Value((b0 >> 3) & 0b111))]
    pub version: u8,
    #[nom(Value(NtpMode(b0 & 0b111)))]
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: u32,
    pub ts_ref: u64,
    pub ts_orig: u64,
    pub ts_recv: u64,
    pub ts_xmit: u64,

    #[nom(Parse = "opt(complete(take(12usize)))")]
    pub authenticator: Option<&'a [u8]>,
}

/// An NTP version 4 packet
#[derive(Debug, PartialEq, NomBE)]
pub struct NtpV4Packet<'a> {
    #[nom(PreExec = "let (i, b0) = be_u8(i)?;")]
    #[nom(Value(b0 >> 6))]
    pub li: u8,
    #[nom(Value((b0 >> 3) & 0b111))]
    pub version: u8,
    #[nom(Value(NtpMode(b0 & 0b111)))]
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: u32,
    pub ts_ref: u64,
    pub ts_orig: u64,
    pub ts_recv: u64,
    pub ts_xmit: u64,

    #[nom(Parse = "try_parse_extensions")]
    pub extensions: Vec<NtpExtension<'a>>,
    #[nom(Cond(!i.is_empty()))]
    pub auth: Option<NtpMac<'a>>,
}

impl<'a> NtpV4Packet<'a> {
    pub fn get_precision(&self) -> f32 {
        2.0_f32.powf(self.precision as f32)
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct NtpExtension<'a> {
    pub field_type: u16,
    pub length: u16,
    #[nom(Parse = "take(length)")]
    pub value: &'a [u8],
    /*padding*/
}

#[derive(Debug, PartialEq, NomBE)]
pub struct NtpMac<'a> {
    pub key_id: u32,
    #[nom(Parse = "take(16usize)")]
    pub mac: &'a [u8],
}

#[inline]
pub fn parse_ntp_extension(i: &[u8]) -> IResult<&[u8], NtpExtension<'_>> {
    NtpExtension::parse(i)
}

// Attempt to parse extensions.
//
// See section 7.5 of [RFC5905] and [RFC7822]:
// In NTPv4, one or more extension fields can be inserted after the
//    header and before the MAC, which is always present when an extension
//    field is present.
//
// So:
//  if == 20, only MAC
//  if >  20, ext + MAC
//  if ==  0, nothing
//  else      error
fn try_parse_extensions(i: &[u8]) -> IResult<&[u8], Vec<NtpExtension<'_>>> {
    if i.is_empty() || i.len() == 20 {
        // if empty, or if remaining length is exactly the MAC length (20), assume we do not have
        // extensions
        return Ok((i, Vec::new()));
    }
    if i.len() < 20 {
        return Err(Err::Error(make_error(i, ErrorKind::Eof)));
    }
    map_parser(take(i.len() - 20), many1(complete(parse_ntp_extension)))(i)
}

/// Parse an NTP version 3 packet (RFC 1305)
#[inline]
pub fn parse_ntpv3(i: &[u8]) -> IResult<&[u8], NtpV3Packet<'_>> {
    NtpV3Packet::parse(i)
}

/// Parse an NTP version 4 packet (RFC 1305)
#[inline]
pub fn parse_ntpv4(i: &[u8]) -> IResult<&[u8], NtpV4Packet<'_>> {
    NtpV4Packet::parse(i)
}

/// Parse an NTP packet, version 3 or 4
#[inline]
pub fn parse_ntp(i: &[u8]) -> IResult<&[u8], NtpPacket<'_>> {
    let (_, b0) = be_u8(i)?;
    match (b0 >> 3) & 0b111 {
        3 => map(NtpV3Packet::parse, NtpPacket::V3)(i),
        4 => map(NtpV4Packet::parse, NtpPacket::V4)(i),
        _ => Err(Err::Error(make_error(i, ErrorKind::Tag))),
    }
}

#[cfg(test)]
mod tests {
    use crate::ntp::*;

    static NTP_REQ1: &[u8] = &[
        0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x90, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec,
        0x42, 0xee, 0x92,
    ];

    #[test]
    fn test_ntp_packet_simple() {
        let empty = &b""[..];
        let bytes = NTP_REQ1;
        let expected = NtpV4Packet {
            li: 3,
            version: 3,
            mode: NtpMode::SymmetricActive,
            stratum: 0,
            poll: 10,
            precision: -6,
            root_delay: 0,
            root_dispersion: 0x010290,
            ref_id: 0,
            ts_ref: 0,
            ts_orig: 0,
            ts_recv: 0,
            ts_xmit: 14195914391047827090u64,
            extensions: Vec::new(),
            auth: None,
        };
        let res = parse_ntpv4(&bytes);
        assert_eq!(res, Ok((empty, expected)));
    }

    static NTP_REQ2: &[u8] = &[
        0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x25, 0xcc, 0x13, 0x2b,
        0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x80, 0x0c, 0x2b, 0x59, 0x00, 0x64, 0x66,
        0x84, 0xf4, 0x4c, 0xa4, 0xee, 0xce, 0x12, 0xb8,
    ];

    #[test]
    fn test_ntp_packet_mac() {
        let empty = &b""[..];
        let bytes = NTP_REQ2;
        let expected = NtpV4Packet {
            li: 0,
            version: 4,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 12,
            root_dispersion: 0,
            ref_id: 0,
            ts_ref: 0,
            ts_orig: 0,
            ts_recv: 0,
            ts_xmit: 14710388140573593600,
            extensions: Vec::new(),
            auth: Some(NtpMac {
                key_id: 1,
                mac: &bytes[52..],
            }),
        };
        let res = parse_ntpv4(&bytes);
        assert_eq!(res, Ok((empty, expected)));
    }

    static NTP_REQ2B: &[u8] = &[
        0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x25, 0xcc, 0x13, 0x2b,
        0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x80, 0x0c, 0x2b,
        0x59, 0x00, 0x64, 0x66, 0x84, 0xf4, 0x4c, 0xa4, 0xee, 0xce, 0x12, 0xb8,
    ];

    #[test]
    fn test_ntp_packet_extension() {
        let empty = &b""[..];
        let bytes = NTP_REQ2B;
        let expected = NtpV4Packet {
            li: 0,
            version: 4,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 12,
            root_dispersion: 0,
            ref_id: 0,
            ts_ref: 0,
            ts_orig: 0,
            ts_recv: 0,
            ts_xmit: 14710388140573593600,
            extensions: vec![NtpExtension {
                field_type: 0,
                length: 0,
                value: empty,
            }],
            auth: Some(NtpMac {
                key_id: 1,
                mac: &bytes[56..],
            }),
        };
        let res = parse_ntpv4(&bytes);
        assert_eq!(res, Ok((empty, expected)));
    }

    // from wireshark test captures 'ntp.pcap'
    static NTPV3_REQ: &[u8] = &[
        0x1b, 0x04, 0x06, 0xf5, 0x00, 0x00, 0x10, 0x0d, 0x00, 0x00, 0x05, 0x57, 0x82, 0xdc, 0x18,
        0x18, 0xba, 0x29, 0x66, 0x36, 0x7d, 0xd0, 0x00, 0x00, 0xba, 0x29, 0x66, 0x36, 0x7d, 0x58,
        0x40, 0x00, 0xba, 0x29, 0x66, 0x36, 0x7d, 0xd0, 0x00, 0x00, 0xba, 0x29, 0x66, 0x76, 0x7d,
        0x50, 0x50, 0x00,
    ];

    #[test]
    fn test_ntp_packet_v3() {
        let empty = &b""[..];
        let bytes = NTPV3_REQ;
        let expected = NtpV3Packet {
            li: 0,
            version: 3,
            mode: NtpMode::Client,
            stratum: 4,
            poll: 6,
            precision: -11,
            root_delay: 4109,
            root_dispersion: 0x0557,
            ref_id: 0x82dc1818,
            ts_ref: 0xba296636_7dd00000,
            ts_orig: 0xba296636_7d584000,
            ts_recv: 0xba296636_7dd00000,
            ts_xmit: 0xba296676_7d505000,
            authenticator: None,
        };
        let res = NtpV3Packet::parse(&bytes);
        assert_eq!(res, Ok((empty, expected)));
    }
}
