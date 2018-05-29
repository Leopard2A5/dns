extern crate num;
#[macro_use] extern crate enum_primitive;
extern crate rand;
extern crate serde;
#[macro_use] extern crate serde_derive;

mod dns_record;
mod builder;
mod enums;
mod errors;
mod labels;
mod utils;

pub type ParsedQuestion<'a> = dns_record::Question<'a>;

pub use self::dns_record::{
    parse,
    Record,
    RecordPayload,
};

pub use self::enums::*;
pub use self::errors::*;
pub use self::builder::*;
pub use self::builder::Question;
