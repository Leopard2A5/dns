use ::enums::{Qtype, Qclass};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Question<'a> {
    pub labels: Vec<Cow<'a, str>>,
    pub qtype: Qtype,
    pub qclass: Qclass
}

impl<'a> Question<'a> {
    pub fn new<T>(
        labels: T,
        qtype: Qtype,
        qclass: Qclass
    ) -> Question<'a>
    where T: IntoIterator,
          T::Item: Into<Cow<'a, str>>
    {
        let labels = labels.into_iter()
            .map(|t| t.into())
            .collect();
        Question { labels, qtype, qclass }
    }
}
