mod question;
mod parser;
mod dns_record;
mod record_preamble;
mod arecord;

pub use self::parser::parse;
pub use self::question::Question;
pub use self::arecord::ARecord;
