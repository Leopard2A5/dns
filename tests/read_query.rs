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

    let result = parse(&buffer).unwrap();
    assert!(result.id() > 0);
    assert_eq!(QR::QUERY, result.qr());
    assert_eq!(OPCODE::QUERY, result.opcode());
    assert!(result.rd());
    assert_eq!(1, result.questions().len());
}
