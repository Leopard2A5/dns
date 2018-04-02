use std::result;
use std::borrow::Cow;

#[derive(Debug, PartialEq, Eq)]
pub enum DnsMsgError {
    InvalidData,
    CyclicLabelRef
}

#[derive(Debug, PartialEq, Eq)]
pub struct Error<'a> {
    pub kind: DnsMsgError,
    pub msg:Cow<'a, str>
}

impl<'a> Error<'a> {
    pub fn new<M>(kind: DnsMsgError, msg: M) -> Self
        where M: Into<Cow<'a, str>> {
        Self {
            kind,
            msg: msg.into()
        }
    }
}

pub type Result<'a, T> = result::Result<T, Error<'a>>;
