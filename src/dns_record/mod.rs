mod question;

use self::question::*;
use ::enums::*;
use ::errors::*;
use std::collections::VecDeque;
use num::FromPrimitive;

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
        Ok(Question { labels, qtype, qclass })
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

enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum QR {
        QUERY    = 0,
        RESPONSE = 1
    }
}

enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum OPCODE {
        QUERY  = 0,
        IQUERY = 1,
        STATUS = 2
    }
}

enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum RCODE {
        Ok              = 0,
        FormatError     = 1,
        ServerFailure   = 2,
        NameError       = 3,
        NotImplemented  = 4,
        Refused         = 5
    }
}

#[cfg(test)]
mod test {
    use super::*;

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

    fn encode_label(text: &str) -> Vec<u8> {
        use std::ffi::CString;

        let mut ret = vec![];
        let text = CString::new(text).unwrap();
        let bytes = text.as_bytes();

        ret.push(bytes.len() as u8);
        ret.extend(bytes.iter());

        ret
    }

    fn encode_labels(texts: Vec<&str>) -> Vec<u8> {
        let mut ret = texts.iter()
            .map(|txt| encode_label(txt))
            .fold(vec![], |mut a, t| { a.extend(t.iter()); a });

        ret.push(0);
        ret
    }

    #[test]
    fn should_read_one_question() {
        let mut buffer = [0u8; 512];
        buffer[5] = 1; // 1 question

        let labels = encode_labels(vec!["www", "google", "com"]);

        let end = 12 + labels.len();
        buffer[12..end].copy_from_slice(&labels);
        buffer[end+1] = Qtype::A as u8;
        buffer[end+3] = Qclass::IN as u8;

        let expected = Question {
            labels: vec!["www", "google", "com"],
            qtype: Qtype::A,
            qclass: Qclass::IN
        };

        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(vec![expected]), rec.questions());
    }

    #[test]
    fn should_read_multiple_questions() {
        let mut buffer = [0u8; 512];
        buffer[5] = 2; // 2 questions

        let labels = encode_labels(vec!["www", "google", "com"]);
        let end = 12 + labels.len();
        buffer[12..end].copy_from_slice(&labels);
        buffer[end+1] = Qtype::A as u8;
        buffer[end+3] = Qclass::IN as u8;

        let labels = encode_labels(vec!["www", "heise", "de"]);
        let start = end + 4;
        let end = start + labels.len();
        buffer[start..end].copy_from_slice(&labels);
        buffer[end+1] = Qtype::NS as u8;
        buffer[end+3] = Qclass::CS as u8;

        let expected = vec![
            Question {
                labels: vec!["www", "google", "com"],
                qtype: Qtype::A,
                qclass: Qclass::IN
            },
            Question {
                labels: vec!["www", "heise", "de"],
                qtype: Qtype::NS,
                qclass: Qclass::CS
            }
        ];

        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(expected), rec.questions());
    }

    #[test]
    fn should_read_questions_with_label_refs() {
        let mut buffer = [0u8; 512];
        buffer[5] = 1; // 1 question

        let labels = encode_labels(vec!["aaa", "xxx"]);

        let mut end = 12 + labels.len();
        buffer[12..end].copy_from_slice(&labels);

        // one more element, override 0 terminator
        buffer[end-1] = 0xc0;
        buffer[end] = 12; // jump to 12

        buffer[end+1] = 0xc0;
        buffer[end+2] = 16; // jump to 16

        end += 3;
        let labels = encode_labels(vec!["fff"]);
        buffer[end..end+labels.len()].copy_from_slice(&labels);
        end += labels.len();

        buffer[end] = 0; // replace 0 terminator

        buffer[end+1] = Qtype::A as u8;
        buffer[end+3] = Qclass::IN as u8;

        let expected = Question {
            labels: vec!["aaa", "xxx", "aaa", "xxx", "fff"],
            qtype: Qtype::A,
            qclass: Qclass::IN
        };

        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(vec![expected]), rec.questions());
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
