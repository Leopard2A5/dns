extern crate num;
#[macro_use] extern crate enum_primitive;

mod dns_record;
mod enums;
mod errors;

pub use self::dns_record::{
    DnsRecord,
    QR,
    OPCODE,
    RCODE
};

pub use self::enums::*;
pub use self::errors::*;
