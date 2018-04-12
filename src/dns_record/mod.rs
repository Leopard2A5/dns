mod question;

use ::enums::*;
use ::errors::*;
use std::collections::VecDeque;
use num::FromPrimitive;

pub use self::question::Question;

pub struct DnsRecord {
    data: [u8; 512]
}

impl DnsRecord {
    pub fn new(data: [u8; 512]) -> Self {
        DnsRecord { data }
    }

    fn read_u16(&self, index: usize) -> u16 {
        assert!(index <= 510, "array index out of bounds!");

        let tmp = &self.data[index] as *const u8;
        unsafe {
            u16::from_be(*(tmp as *const u16))
        }
    }

    pub fn id(&self) -> u16 {
        self.read_u16(0)
    }

    pub fn qr(&self) -> QR {
        let val = self.data[2] >> 7;
        QR::from_u8(val).unwrap()
    }

    pub fn opcode(&self) -> Result<OPCODE> {
        let val = self.data[2] >> 3 & 0x0f;
        OPCODE::from_u8(val)
            .ok_or(Error::new(DnsMsgError::InvalidData, format!("Unknown opcode {}", val)))
    }

    pub fn aa(&self) -> bool {
        (self.data[2] & 0b_0000_0100) > 0
    }

    pub fn tc(&self) -> bool {
        (self.data[2] & 0b_0000_0010) > 0
    }

    pub fn rd(&self) -> bool {
        (self.data[2] & 1) > 0
    }

    pub fn ra(&self) -> bool {
        (self.data[3] & 0b_1000_0000) > 0
    }

    pub fn dnssec_bits(&self) -> u8 {
        self.data[3] >> 4 & 0x0f
    }

    pub fn rcode(&self) -> Result<RCODE> {
        let val = self.data[3] & 0x0f;
        RCODE::from_u8(val)
            .ok_or(Error::new(DnsMsgError::InvalidData, format!("Unknown rcode value {}", val)))
    }

    pub fn qdcount(&self) -> u16 {
        self.read_u16(4)
    }

    pub fn ancount(&self) -> u16 {
        self.read_u16(6)
    }

    pub fn nscount(&self) -> u16 {
        self.read_u16(8)
    }

    pub fn arcount(&self) -> u16 {
        self.read_u16(10)
    }

    fn parse_label(&self, pos: &mut usize, visited_positions: &mut VecDeque<usize>) -> Result<Option<&str>> {
        use std::str;

        visited_positions.push_back(*pos);

        let len = self.data[*pos] as usize;
        *pos += 1;

        if len == 0 {
            return Ok(None);
        }

        if len & 0xc0 == 0xc0 {
            let mut jump = (self.read_u16(*pos - 1) ^ 0xc000) as usize;

            if visited_positions.contains(&jump) {
                return Err(Error::new(DnsMsgError::CyclicLabelRef, "Encountered cyclic label reference"));
            }

            *pos += 1; // advance pos beyond jump addr
            return self.parse_label(&mut jump, visited_positions);
        }

        let ret = str::from_utf8(&self.data[*pos..*pos+len]).unwrap();
        *pos += len;

        Ok(Some(ret))
    }

    fn parse_labels(&self, pos: &mut usize) -> Result<Vec<&str>> {
        let mut labels = vec![];
        loop {
            let mut visited_positions = VecDeque::new();

            if let Some(lbl) = self.parse_label(pos, &mut visited_positions)? {
                labels.push(lbl);
            } else {
                break;
            }
        }

        Ok(labels)
    }

    fn parse_question(&self, pos: &mut usize) -> Result<Question> {
        let labels = self.parse_labels(pos)?;

        let qtype = self.read_u16(*pos);
        let qtype = Qtype::from_u16(qtype).unwrap();

        *pos += 2;
        let qclass = self.read_u16(*pos);
        let qclass = Qclass::from_u16(qclass).unwrap();

        *pos += 2;
        Ok(Question::new(labels, qtype, qclass))
    }

    pub fn questions(&self) -> Result<Vec<Question>> {
        let mut pos = 12;
        let mut questions = vec![];

        for _ in 0..self.qdcount() {
            questions.push(self.parse_question(&mut pos)?);
        }

        Ok(questions)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::labels::encode_labels;
    use ::utils::write_u16;
    use std::collections::HashMap;

    #[test]
    fn should_read_id() {
        let mut buffer = [0u8; 512];
        let rec = DnsRecord::new(buffer);
        assert_eq!(0u16, rec.id());

        buffer[1] = 1;
        buffer[0] = 1;
        let rec = DnsRecord::new(buffer);
        assert_eq!(0x0101u16, rec.id());
    }

    #[test]
    fn should_read_qr() {
        let mut buffer = [0u8; 512];
        buffer[0] = 0xff;
        buffer[1] = 0xff;

        let rec = DnsRecord::new(buffer);
        assert_eq!(QR::QUERY, rec.qr());

        buffer[2] = 0xa0;
        let rec = DnsRecord::new(buffer);
        assert_eq!(QR::RESPONSE, rec.qr());
    }

    #[test]
    fn should_read_opcodes() {
        let mut buffer = [0u8; 512];

        // 1 are the relevant bits for opcode in the third byte
        // 0111 1000
        // 0000 0000 = 0x00 0: query
        // 0000 1000 = 0x08 1: iquery
        // 0001 0000 = 0x10 2: status

        buffer[2] = 1;
        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(OPCODE::QUERY), rec.opcode());

        buffer[2] = 1 << 3;
        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(OPCODE::IQUERY), rec.opcode());

        buffer[2] = 2 << 3;
        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(OPCODE::STATUS), rec.opcode());

        for i in 3..16 {
            buffer[2] = i << 3;
            let rec = DnsRecord::new(buffer);
            let msg = format!("Unknown opcode {}", i);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, msg)), rec.opcode());
        }
    }

    #[test]
    fn should_read_authoritative_answer() {
        let mut buffer = [0u8; 512];
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.aa());

        buffer[2] = 0b_0000_0100;
        let rec = DnsRecord::new(buffer);
        assert_eq!(true, rec.aa());
    }

    #[test]
    fn should_read_truncated_message() {
        let mut buffer = [0u8; 512];
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.tc());

        buffer[2] = 0b_0000_0010;
        let rec = DnsRecord::new(buffer);
        assert_eq!(true, rec.tc());
    }

    #[test]
    fn should_read_recursion_desired() {
        let mut buffer = [0u8; 512];
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.rd());

        buffer[2] = 1;
        let rec = DnsRecord::new(buffer);
        assert_eq!(true, rec.rd());
    }

    #[test]
    fn should_read_recursion_available() {
        let mut buffer = [0u8; 512];
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.ra());

        buffer[3] = 0b_1000_0000;
        let rec = DnsRecord::new(buffer);
        assert_eq!(true, rec.ra());
    }

    #[test]
    fn should_read_dnssec_bits() {
        let mut buffer = [0u8; 512];

        for i in 0..9 {
            buffer[3] = i << 4;
            let rec = DnsRecord::new(buffer);
            assert_eq!(i, rec.dnssec_bits());
        }
    }

    #[test]
    fn should_read_response_code() {
        let mut buffer = [0u8; 512];

        let values = vec![
            (0, RCODE::Ok),
            (1, RCODE::FormatError),
            (2, RCODE::ServerFailure),
            (3, RCODE::NameError),
            (4, RCODE::NotImplemented),
            (5, RCODE::Refused)
        ];

        for (i, val) in values {
            buffer[3] = i;
            let rec = DnsRecord::new(buffer);
            assert_eq!(Ok(val), rec.rcode());
        }
        for i in 6..16 {
            buffer[3] = i;
            let rec = DnsRecord::new(buffer);
            let msg = format!("Unknown rcode value {}", i);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, msg)), rec.rcode());
        }
    }

    #[test]
    fn should_read_num_questions() {
        let mut buffer = [0u8; 512];
        buffer[4] = 1;
        buffer[5] = 2;
        let rec = DnsRecord::new(buffer);
        assert_eq!(258, rec.qdcount());
    }

    #[test]
    fn should_read_num_answers() {
        let mut buffer = [0u8; 512];
        buffer[6] = 1;
        buffer[7] = 3;
        let rec = DnsRecord::new(buffer);
        assert_eq!(259, rec.ancount());
    }

    #[test]
    fn should_read_num_authority() {
        let mut buffer = [0u8; 512];
        buffer[8] = 1;
        buffer[9] = 4;
        let rec = DnsRecord::new(buffer);
        assert_eq!(260, rec.nscount());
    }

    #[test]
    fn should_read_num_additional() {
        let mut buffer = [0u8; 512];
        buffer[10] = 1;
        buffer[11] = 5;
        let rec = DnsRecord::new(buffer);
        assert_eq!(261, rec.arcount());
    }

    #[test]
    fn should_read_one_question() {
        let mut buffer = [0u8; 512];
        buffer[5] = 1; // 1 question

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["www", "google", "com"]);
        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

        let expected = Question::new(
            vec!["www", "google", "com"],
            Qtype::A,
            Qclass::IN
        );

        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(vec![expected]), rec.questions());
    }

    #[test]
    fn should_read_multiple_questions() {
        let mut buffer = [0u8; 512];
        buffer[5] = 2; // 2 questions

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["www", "google", "com"]);
        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);
        println!("{:?}", &buffer[12..pos+4]);

        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["www", "heise", "de"]);
        write_u16(&mut buffer, &mut pos, Qtype::NS as u16);
        write_u16(&mut buffer, &mut pos, Qclass::CS as u16);

        let expected = vec![
            Question::new(
                vec!["www", "google", "com"],
                Qtype::A,
                Qclass::IN
            ),
            Question::new(
                vec!["www", "heise", "de"],
                Qtype::NS,
                Qclass::CS
            )
        ];

        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(expected), rec.questions());
    }

    #[test]
    fn should_read_questions_with_label_refs() {
        let mut buffer = [0u8; 512];
        buffer[5] = 1; // 1 question

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["aaa", "xxx"]);

        // one more element, override 0 terminator
        buffer[pos-1] = 0xc0;
        buffer[pos] = 12; // jump to 12

        buffer[pos+1] = 0xc0;
        buffer[pos+2] = 16; // jump to 16

        pos += 3;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["fff"]);

        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

        let expected = Question::new(
            vec!["aaa", "xxx", "aaa", "xxx", "fff"],
            Qtype::A,
            Qclass::IN
        );

        let rec = DnsRecord::new(buffer);
        let questions = rec.questions().unwrap();
        let q = &questions[0];
        assert_eq!(expected, *q);
    }

    #[test]
    fn should_recognize_cyclic_label_refs() {
        let mut buffer = [0u8; 512];
        buffer[5] = 1; // 1 question

        buffer[12] = 0xc0;
        buffer[13] = 14;
        buffer[14] = 0xc0;
        buffer[15] = 12;
        buffer[16] = 0; // 0 terminator

        buffer[18] = Qtype::A as u8;
        buffer[20] = Qclass::IN as u8;

        let rec = DnsRecord::new(buffer);
        let expected = Err(Error::new(DnsMsgError::CyclicLabelRef, "Encountered cyclic label reference"));
        assert_eq!(expected, rec.questions());
    }
}
