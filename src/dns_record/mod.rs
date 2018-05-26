mod question;
mod parser;
mod dns_record;
mod records;

pub use self::parser::parse;
pub use self::question::Question;
pub use self::records::{Record, RecordPayload};
