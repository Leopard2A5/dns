use std::borrow::Cow;
use ::enums::{Type, Class};

#[derive(Debug, PartialEq, Eq)]
pub struct RecordPreamble<'a> {
    pub labels: Vec<Cow<'a, str>>,
    pub rtype: Type,
    pub class: Class,
    pub ttl: u32,
    pub len: u16,
}

impl <'a> RecordPreamble<'a> {
    pub fn new<T>(
        labels: T,
        rtype: Type,
        class: Class,
        ttl: u32,
        len: u16
    ) -> Self
    where T: IntoIterator,
          T::Item: Into<Cow<'a, str>> {
        let labels = labels.into_iter()
            .map(|i| i.into())
            .collect();
        RecordPreamble { labels, rtype, class, ttl, len }
    }
}
