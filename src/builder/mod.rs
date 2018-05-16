use rand::{Rng, thread_rng};
use ::enums::*;
use ::Question;
use ::labels::*;
use ::utils::write_u16;
use std::collections::HashMap;

#[derive(Debug)]
pub struct DnsMessageBuilder<'a> {
    id: u16,
    qr: QR,
    opcode: OPCODE,
    aa: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: RCODE,
    questions: Vec<Question<'a>>,
}

impl<'a> DnsMessageBuilder<'a> {
    pub fn new() -> Self {
        DnsMessageBuilder {
            id: thread_rng().gen(),
            qr: QR::QUERY,
            opcode: OPCODE::QUERY,
            aa: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: RCODE::Ok,
            questions: vec![],
        }
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn with_qr(mut self, val: QR) -> Self {
        self.qr = val;
        self
    }

    pub fn with_opcode(mut self, val: OPCODE) -> Self {
        self.opcode = val;
        self
    }

    pub fn with_aa(mut self, val: bool) -> Self {
        self.aa = val;
        self
    }

    pub fn with_rd(mut self, val: bool) -> Self {
        self.rd = val;
        self
    }

    pub fn with_ra(mut self, val: bool) -> Self {
        self.ra = val;
        self
    }

    /// Set the message's dnssec (z) bits. Only the three
    /// least significant bits of `val` will be taken into account, i.e.
    /// val should be a right-alined byte.
    pub fn with_dnssec_bits(mut self, val: u8) -> Self {
        self.z = val & 0b_0000_0111;
        self
    }

    pub fn with_rcode(mut self, val: RCODE) -> Self {
        self.rcode = val;
        self
    }

    pub fn add_question(mut self, question: Question<'a>) -> Self {
        self.questions.push(question);
        self
    }

    pub fn build(self) -> [u8; 512] {
        let mut buffer = [0u8; 512];

        write_u16(&mut buffer, &mut 0, self.id);

        buffer[2] = (self.qr as u8) << 7;
        buffer[2] |= (self.opcode as u8) << 3;
        buffer[2] |= (self.aa as u8) << 2;
        // TODO: set truncated message bit
        buffer[2] |= self.rd as u8;

        buffer[3] = (self.ra as u8) << 7;
        buffer[3] |= self.z << 4;
        buffer[3] |= (self.rcode as u8) & 0x0f;

        write_u16(&mut buffer, &mut 4, self.questions.len() as u16);

        let mut pos = 12;
        let mut encoded_labels = HashMap::new();
        for question in self.questions {
            let labels = question.labels;
            encode_labels(&mut buffer, &mut pos, &mut encoded_labels, labels);

            write_u16(&mut buffer, &mut pos, question.qtype as u16);

            write_u16(&mut buffer, &mut pos, question.qclass as u16);
        }

        buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::parse;
    use ::Question;

    #[test]
    fn should_init_with_default_id() {
        use std::collections::HashSet;

        let num_tests = 5;
        let mut ids = HashSet::new();

        for _ in 0..num_tests {
            let buffer = DnsMessageBuilder::new().build();
            let result = parse(&buffer).unwrap();
            ids.insert(result.id());
        }

        assert_eq!(num_tests, ids.len());
    }

    #[test]
    fn should_allow_id_override() {
        let buffer = DnsMessageBuilder::new()
            .with_id(5)
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(5, result.id());
    }

    #[test]
    fn should_default_to_query() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(QR::QUERY, result.qr());
    }

    #[test]
    fn should_allow_qr_override() {
        let buffer = DnsMessageBuilder::new()
            .with_qr(QR::RESPONSE)
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(QR::RESPONSE, result.qr());
    }

    #[test]
    fn should_default_to_query_opcode() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(OPCODE::QUERY, result.opcode());
    }

    #[test]
    fn should_allow_opcode_override() {
        let buffer = DnsMessageBuilder::new()
            .with_opcode(OPCODE::IQUERY)
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(QR::QUERY, result.qr());
        assert_eq!(OPCODE::IQUERY, result.opcode());
    }

    #[test]
    fn should_default_to_non_authoritative_answer() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(false, result.aa());
    }

    #[test]
    fn should_allow_aa_override() {
        let buffer = DnsMessageBuilder::new()
            .with_aa(true)
            .build();
        let result = parse(&buffer).unwrap();
        assert!(result.aa());
    }

    #[test]
    fn should_default_to_non_truncated_message() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(false, result.tc());
    }

    #[test]
    fn should_default_to_no_resultursion_desired() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(false, result.rd());
    }

    #[test]
    fn should_allow_setting_resultursion_desired() {
        let buffer = DnsMessageBuilder::new()
            .with_rd(true)
            .build();
        let result = parse(&buffer).unwrap();
        assert!(result.rd());
    }

    #[test]
    fn should_default_to_no_resultursion_available() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(false, result.ra());
    }

    #[test]
    fn should_allow_setting_resultursion_avaiable() {
        let buffer = DnsMessageBuilder::new()
            .with_ra(true)
            .build();
        let result = parse(&buffer).unwrap();
        assert!(result.ra());
    }

    #[test]
    fn should_default_to_zeroed_dnssec_bits() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(0, result.dnssec() & 0b_0111_0000);
    }

    #[test]
    fn should_allow_setting_dnssec_bits() {
        let buffer = DnsMessageBuilder::new()
            .with_dnssec_bits(0xff)
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(0b_0000_0111, result.dnssec());
    }

    #[test]
    fn should_default_to_response_code_ok() {
        let buffer = DnsMessageBuilder::new().build();
        let result = parse(&buffer).unwrap();
        assert_eq!(RCODE::Ok, result.rcode());
    }

    #[test]
    fn should_allow_setting_the_response_code() {
        let buffer = DnsMessageBuilder::new()
            .with_rcode(RCODE::NotImplemented)
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(RCODE::NotImplemented, result.rcode());
    }

    #[test]
    fn should_allow_adding_questions() {
        let buffer = DnsMessageBuilder::new()
            .add_question(Question::new(
                vec!["www", "aaa"],
                Qtype::MD,
                Qclass::Wildcard
            ))
            .add_question(Question::new(
                vec!["heise", "de"],
                Qtype::A,
                Qclass::IN
            ))
            .build();
        let result = parse(&buffer).unwrap();
        assert_eq!(
            vec![
                Question::new(vec!["www", "aaa"], Qtype::MD, Qclass::Wildcard),
                Question::new(vec!["heise", "de"], Qtype::A, Qclass::IN)
            ],
            result.questions()
        );
    }

    #[test]
    fn should_build_with_label_refs() {
        let buffer = DnsMessageBuilder::new()
            .add_question(Question::new(
                vec!["www"],
                Qtype::MD,
                Qclass::Wildcard
            ))
            .add_question(Question::new(
                vec!["www", "aaa"],
                Qtype::MD,
                Qclass::Wildcard
            ))
            .add_question(Question::new(
                vec!["xxx", "aaa", "bbb"],
                Qtype::MD,
                Qclass::Wildcard
            ))
            .build();

        assert_eq!(&buffer[12..17], &[3, 119, 119, 119, 0]);

        assert_eq!(&buffer[21..23], &[0xc0, 12]);
        assert_eq!(&buffer[23..28], &[3, 97, 97, 97, 0]);

        assert_eq!(&buffer[32..36], &[3, 120, 120, 120]);
        assert_eq!(&buffer[36..38], &[0xc0, 23]);
        assert_eq!(&buffer[38..42], &[3, 98, 98, 98]);
    }
}
