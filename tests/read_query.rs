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

    let rec = DnsRecord::new(buffer);
    assert!(rec.id() > 0);
    assert_eq!(QR::QUERY, rec.qr());
    assert_eq!(Ok(OPCODE::QUERY), rec.opcode());
    assert!(rec.rd());
    assert_eq!(1, rec.qdcount());
}
