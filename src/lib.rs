extern crate num;
#[macro_use] extern crate enum_primitive;

mod dns_record;

pub use self::dns_record::{
    DnsRecord,
    DnsMsgError,
    Error,
    Result,
    QR,
    OPCODE,
    RCODE
};
