use std::net::Ipv4Addr;
use std::borrow::Cow;
use ::enums::Class;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Record<'a> {
    pub labels: Vec<Cow<'a, str>>,
    pub class: Class,
    pub ttl: u32,
    pub payload: RecordPayload
}

impl<'a> Record<'a> {
    pub fn new<L>(
        labels: L,
        class: Class,
        ttl: u32,
        payload: RecordPayload
    ) -> Self
    where L: IntoIterator,
          L::Item: Into<Cow<'a, str>>
    {
        let labels = labels.into_iter()
            .map(|l| l.into())
            .collect();
        Record { labels, class, ttl, payload }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub enum RecordPayload {
    A(Ipv4Addr),
}
