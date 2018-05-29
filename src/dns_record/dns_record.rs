use ::enums::*;
use ::ParsedQuestion;
use ::dns_record::records::Record;

#[derive(Debug, PartialEq, Eq)]
pub struct DnsRecord<'a> {
    id: u16,
    qr: QR,
    opcode: OPCODE,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    dnssec: u8,
    rcode: RCODE,
    questions: Vec<ParsedQuestion<'a>>,
    answers: Vec<Record<'a>>,
}

impl<'a> DnsRecord<'a> {
    pub fn new(
        id: u16,
        qr: QR,
        opcode: OPCODE,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        dnssec: u8,
        rcode: RCODE,
        questions: Vec<ParsedQuestion<'a>>,
        answers: Vec<Record<'a>>,
    ) -> Self {
        DnsRecord {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            dnssec,
            rcode,
            questions,
            answers,
        }
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn qr(&self) -> QR {
        self.qr
    }

    pub fn opcode(&self) -> OPCODE {
        self.opcode
    }

    pub fn aa(&self) -> bool {
        self.aa
    }

    pub fn tc(&self) -> bool {
        self.tc
    }

    pub fn rd(&self) -> bool {
        self.rd
    }

    pub fn ra(&self) -> bool {
        self.ra
    }

    pub fn dnssec(&self) -> u8 {
        self.dnssec
    }

    pub fn rcode(&self) -> RCODE {
        self.rcode
    }

    pub fn questions(&self) -> &[ParsedQuestion<'a>] {
        &self.questions
    }

    pub fn answers(&self) -> &[Record<'a>] {
        &self.answers
    }
}
