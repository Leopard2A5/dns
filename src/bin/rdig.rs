extern crate dns;

use dns::DnsMessageBuilder;
use dns::Question;
use dns::{Qtype, Qclass};
use dns::parse;
use std::net::UdpSocket;
use std::fs::File;
use std::io::Read;

fn main() -> std::io::Result<()> {
    let mut reference = vec![];
    let mut file = File::open("tests/dnsquery.txt").unwrap();
    file.read_to_end(&mut reference).unwrap();

    println!("reference:");
    println!("{:?}", parse(&reference).unwrap());

    let bytes = DnsMessageBuilder::new()
        .add_question(Question::new("google.com", Qtype::A, Qclass::IN))
        .with_rd(true)
        .build();

    println!("query:");
    println!("{:?}", parse(&bytes).unwrap());

    let mut socket = UdpSocket::bind("0.0.0.0:3400")?;
    socket.send_to(&bytes, "8.8.8.8:53")?;
    let mut buffer = [0u8; 512];
    socket.recv(&mut buffer);

    let result = parse(&buffer);
    println!("{:?}", result);

    Ok(())
}
