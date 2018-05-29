use ::enums::{Qclass, Qtype};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Question<'a> {
    pub address: &'a str,
    pub qtype: Qtype,
    pub qclass: Qclass
}

impl<'a> Question<'a> {
    pub fn new(
        address: &'a str,
        qtype: Qtype,
        qclass: Qclass
    ) -> Self {
        Question { address, qtype, qclass }
    }
}
