use nom::{be_i8,be_u8};

#[derive(Debug,PartialEq)]
pub struct NtpPacket<'a> {
    li: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: i8,
    precision: i8,
    root_delay: u32,
    root_dispersion: u32,
    ref_id:u32,
    ts_ref:u64,
    ts_orig:u64,
    ts_recv:u64,
    ts_xmit:u64,

    extensions:Vec<NtpExtension<'a>>,

    auth: Option<(u32,&'a[u8])>,
}

impl<'a> NtpPacket<'a> {
    pub fn get_precision(&self) -> f32 {
        2.0_f32.powf(self.precision as f32)
    }
}

#[derive(Debug,PartialEq)]
pub struct NtpExtension<'a> {
    field_type: u16,
    length: u16,
    value: &'a[u8],
    /*padding*/
}

named!(pub parse_ntp_extension<NtpExtension>,
    chain!(
        ty: u16!(true) ~
        len: u16!(true) ~ // len includes the padding
        data: take!(len),
        || {
            NtpExtension{
                field_type:ty,
                length:len,
                value:data,
            }
        })
);

named!(pub parse_ntp<NtpPacket>,
   chain!(
       b0: bits!(
            tuple!(take_bits!(u8,2),take_bits!(u8,3),take_bits!(u8,3))
           ) ~
       st: be_u8 ~
       pl: be_i8 ~
       pr: be_i8 ~
       rde: u32!(true) ~
       rdi: u32!(true) ~
       rid: u32!(true) ~
       tsr: u64!(true) ~
       tso: u64!(true) ~
       tsv: u64!(true) ~
       tsx: u64!(true) ~
       // optional fields, See section 7.5 of [RFC5905] and [RFC7822]
       ext: many0!(complete!(parse_ntp_extension)) ~
       // key ID and MAC
       auth: opt!(complete!(pair!(u32!(true),take!(16)))),
       || {
           NtpPacket {
               li:b0.0,
               version:b0.1,
               mode:b0.2,
               stratum:st,
               poll:pl,
               precision:pr,
               root_delay:rde,
               root_dispersion:rdi,
               ref_id:rid,
               ts_ref:tsr,
               ts_orig:tso,
               ts_recv:tsv,
               ts_xmit:tsx,
               extensions:ext,
               auth:auth,
           }
   })
);

#[cfg(test)]
mod tests {
    use ntp::*;
    use nom::IResult;
    extern crate env_logger;

static NTP_REQ1: &'static [u8] = &[
    0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x90,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42, 0xee, 0x92
];

#[test]
fn test_ntp_packet1() {
    let _ = env_logger::init();
    let empty = &b""[..];
    let bytes = NTP_REQ1;
    let expected = IResult::Done(empty,NtpPacket{
        li:3,
        version:3,
        mode:1,
        stratum:0,
        poll:10,
        precision:-6,
        root_delay:0,
        root_dispersion:0x010290,
        ref_id:0,
        ts_ref:0,
        ts_orig:0,
        ts_recv:0,
        ts_xmit:14195914391047827090u64,
        extensions:vec![],
        auth:None,
    });
    let res = parse_ntp(&bytes);
    assert_eq!(res, expected);
}
}
