use nom::bytes::streaming::take;
use nom::combinator::{complete, map_parser};
use nom::error::{make_error, ErrorKind};
use nom::multi::many1;
use nom::number::streaming::be_u8;
pub use nom::{Err, IResult};
use nom_derive::Nom;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Nom)]
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

#[derive(Debug, PartialEq, Nom)]
pub struct NtpPacket<'a> {
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
    #[nom(Cond(i.len() > 0))]
    pub auth: Option<NtpMac<'a>>,
}

impl<'a> NtpPacket<'a> {
    pub fn get_precision(&self) -> f32 {
        2.0_f32.powf(self.precision as f32)
    }
}

#[derive(Debug, PartialEq, Nom)]
pub struct NtpExtension<'a> {
    pub field_type: u16,
    pub length: u16,
    #[nom(Parse = "take(length)")]
    pub value: &'a [u8],
    /*padding*/
}

#[derive(Debug, PartialEq, Nom)]
pub struct NtpMac<'a> {
    pub key_id: u32,
    #[nom(Parse = "take(16usize)")]
    pub mac: &'a [u8],
}

#[inline]
pub fn parse_ntp_extension(i: &[u8]) -> IResult<&[u8], NtpExtension> {
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
fn try_parse_extensions(i: &[u8]) -> IResult<&[u8], Vec<NtpExtension>> {
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

#[inline]
pub fn parse_ntp(i: &[u8]) -> IResult<&[u8], NtpPacket> {
    NtpPacket::parse(i)
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
        let expected = NtpPacket {
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
        let res = parse_ntp(&bytes);
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
        let expected = NtpPacket {
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
        let res = parse_ntp(&bytes);
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
        let expected = NtpPacket {
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
        let res = parse_ntp(&bytes);
        assert_eq!(res, Ok((empty, expected)));
    }
}
