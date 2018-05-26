extern crate dns;

use dns::*;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

#[test]
fn read_response() {
    let mut bytes = vec![];
    let mut file = File::open("tests/response_packet.txt").unwrap();
    file.read_to_end(&mut bytes).unwrap();

    let result = parse(&bytes).unwrap();
    assert_eq!(
        result.answers(),
        &[
            dns::Record::new(
                vec!["google", "com"],
                Class::IN,
                299,
                dns::RecordPayload::A(Ipv4Addr::new(172, 217, 22, 78))
            )
        ]
    );
}
