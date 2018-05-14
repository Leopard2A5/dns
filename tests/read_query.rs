extern crate dns;

use dns::*;
use std::fs::File;
use std::io::Read;

#[test]
fn check_header() {
    let mut buffer = [0u8; 512];
    {
        let mut file = File::open("tests/dnsquery.txt").unwrap();
        file.read(&mut buffer).unwrap();
    }

    let parser = Parser::new(buffer);
    assert!(parser.id() > 0);
    assert_eq!(QR::QUERY, parser.qr());
    assert_eq!(Ok(OPCODE::QUERY), parser.opcode());
    assert!(parser.rd());
    assert_eq!(1, parser.qdcount());
}
