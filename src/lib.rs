extern crate num;
#[macro_use] extern crate enum_primitive;
extern crate rand;

mod dns_record;
mod builder;
mod enums;
mod errors;
mod labels;
mod utils;

pub use self::dns_record::{
    parse,
    Question,
    Record,
    RecordPayload,
};

pub use self::enums::*;
pub use self::errors::*;
pub use self::builder::*;
