extern crate dns;

use dns::*;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::borrow::Cow;

#[test]
fn read_response() {
    let mut bytes = vec![];
    let mut file = File::open("tests/response_packet.txt").unwrap();
    file.read_to_end(&mut bytes);

    let result = parse(&bytes).unwrap();
    assert_eq!(
        result.answers(),
        &[
            dns::ARecord::new(
                vec!["google", "com"],
                Class::IN,
                299,
                Ipv4Addr::new(172, 217, 22, 78)
            )
        ]
    );
}
