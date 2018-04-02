extern crate num;
#[macro_use] extern crate enum_primitive;

mod dns_record;
mod enums;

pub use self::dns_record::{
    DnsRecord,
    DnsMsgError,
    Error,
    Result,
    QR,
    OPCODE,
    RCODE
};

pub use self::enums::*;
