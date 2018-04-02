use ::enums::{Qtype, Qclass};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question<'a> {
    pub labels: Vec<&'a str>,
    pub qtype: Qtype,
    pub qclass: Qclass
}
