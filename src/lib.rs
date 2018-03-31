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
