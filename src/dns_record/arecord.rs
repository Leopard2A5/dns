use dns_record::record_preamble::RecordPreamble;
use std::net::Ipv4Addr;
use std::borrow::Cow;
use enums::{Type, Class};


#[derive(Debug, PartialEq, Eq)]
pub struct ARecord<'a> {
    preamble: RecordPreamble<'a>,
    ip: Ipv4Addr
}

impl <'a> ARecord<'a> {
    pub fn new<L, I>(
        labels: L,
        class: Class,
        ttl: u32,
        ip: I
    ) -> Self
    where L: IntoIterator,
          L::Item: Into<Cow<'a, str>>,
          I: Into<Ipv4Addr> {
        let preamble = RecordPreamble::new(
            labels,
            Type::A,
            class,
            ttl,
            4
        );
        let ip = ip.into();
        ARecord { preamble, ip }
    }
}
