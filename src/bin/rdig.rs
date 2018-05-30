extern crate dns;
#[macro_use] extern crate clap;
extern crate serde;
extern crate serde_json;

use dns::DnsMessageBuilder;
use dns::Question;
use dns::{Qtype, Qclass};
use dns::parse;
use std::net::UdpSocket;
use clap::{App, Arg};

fn main() {
    let matches = App::new("rdig")
        .version(env!("CARGO_PKG_VERSION"))
        .author("René Perschon <rperschon85@gmail.com>")
        .about("rust dig impl")
        .arg(Arg::with_name("recurse")
            .short("r")
            .long("recurse")
            .help("Whether recursion is desired")
            .default_value("true"))
        .arg(Arg::with_name("address")
            .index(1)
            .help("The address to dig")
            .required(true))
        .get_matches();

    let bytes = DnsMessageBuilder::new()
        .add_question(Question::new(
            &value_t_or_exit!(matches, "address", String),
            Qtype::A,
            Qclass::IN))
        .with_rd(value_t_or_exit!(matches, "recurse", bool))
        .build();

    let mut socket = UdpSocket::bind("0.0.0.0:34000")
        .expect("Could not bind to 0.0.0.0:34000");
    socket.send_to(&bytes, "8.8.8.8:53")
        .expect("Failed to send packet to 8.8.8.8:53");
    let mut buffer = [0u8; 512];
    socket.recv(&mut buffer);

    match parse(&buffer) {
        Ok(answer) => {
            let json = serde_json::to_string_pretty(&answer).unwrap();
            println!("{}", json);
        },
        Err(e) => {
            eprintln!("Error: {:?}: {}", e.kind, &e.msg);
            std::process::exit(1);
        }
    };
}
