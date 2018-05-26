use ::enums::*;
use ::errors::*;
use ::Question;
use std::collections::HashSet;
use ::dns_record::dns_record::DnsRecord;
use ::dns_record::records::Record;
use ::dns_record::records::RecordPayload;
use num::FromPrimitive;
use std::net::Ipv4Addr;
use std::str;

pub fn parse<'a>(data: &'a [u8]) -> Result<'a, DnsRecord<'a>> {
    let mut pos = 12;

    Ok(DnsRecord::new(
        id(data),
        qr(data),
        opcode(data)?,
        aa(data),
        tc(data),
        rd(data),
        ra(data),
        dnssec_bits(data),
        rcode(data)?,
        questions(data, &mut pos)?,
        answers(data, &mut pos)?
    ))
}

fn read_u8<'a>(
    data: &'a [u8],
    index: &mut usize
) -> u8 {
    assert!(*index <= data.len() - 1, "array index out of bounds!");
    *index += 1;
    data[*index - 1]
}

fn read_u16<'a>(
    data: &'a [u8],
    index: &mut usize
) -> u16 {
    assert!(*index <= data.len() - 2, "array index out of bounds!");

    let tmp = &data[*index] as *const u8;
    let tmp = tmp as *const u16;
    *index += 2;
    unsafe {
        u16::from_be(*tmp)
    }
}

fn read_u32<'a>(
    data: &'a [u8],
    index: &mut usize
) -> u32 {
    assert!(*index <= data.len() - 4, "array index out of bounds!");

    let tmp = &data[*index] as *const u8;
    let tmp = tmp as *const u32;
    *index += 4;
    unsafe {
        u32::from_be(*tmp)
    }
}

fn id<'a>(data: &'a [u8]) -> u16 {
    read_u16(data, &mut 0)
}

fn qr<'a>(data: &'a [u8]) -> QR {
    let val = data[2] >> 7;
    QR::from_u8(val).unwrap()
}

fn opcode<'a, 'b>(data: &'a [u8]) -> Result<'b, OPCODE> {
    let val = data[2] >> 3 & 0x0f;
    OPCODE::from_u8(val)
        .ok_or(Error::new(DnsMsgError::InvalidData, format!("Unknown opcode {}", val)))
}

fn aa<'a>(data: &'a [u8]) -> bool {
    (data[2] & 0b_0000_0100) > 0
}

fn tc<'a>(data: &'a [u8]) -> bool {
    (data[2] & 0b_0000_0010) > 0
}

fn rd<'a>(data: &'a [u8]) -> bool {
    (data[2] & 1) > 0
}

fn ra<'a>(data: &'a [u8]) -> bool {
    (data[3] & 0b_1000_0000) > 0
}

fn dnssec_bits<'a>(data: &'a [u8]) -> u8 {
    data[3] >> 4 & 0x0f
}

fn rcode<'a, 'b>(data: &'a [u8]) -> Result<'b, RCODE> {
    let val = data[3] & 0x0f;
    RCODE::from_u8(val)
        .ok_or(Error::new(DnsMsgError::InvalidData, format!("Unknown rcode value {}", val)))
}

fn qdcount<'a>(data: &'a [u8]) -> u16 {
    read_u16(data, &mut 4)
}

fn ancount<'a>(data: &'a [u8]) -> u16 {
    read_u16(data, &mut 6)
}

fn nscount<'a>(data: &'a [u8]) -> u16 {
    read_u16(data, &mut 8)
}

fn arcount<'a>(data: &'a [u8]) -> u16 {
    read_u16(data, &mut 10)
}

fn parse_labels<'a>(
    data: &'a [u8],
    pos: &mut usize,
    prior_jumps: &mut HashSet<usize>
) -> Result<'a, Vec<&'a str>> {
    if data[*pos] & 0xc0 == 0xc0 {
        let mut jump = (read_u16(data, pos) ^ 0xc000) as usize;
        if prior_jumps.contains(&jump) {
            return Err(Error::new(
                DnsMsgError::CyclicLabelRef,
                format!("Encountered cyclic label reference at index {}", *pos)
            ));
        }
        prior_jumps.insert(jump);
        return parse_labels(data, &mut jump, prior_jumps);
    }

    let mut labels = vec![];
    loop {
        let len = read_u8(data, pos) as usize;
        if len == 0 {
            break;
        } else {
            let lbl = str::from_utf8(&data[*pos..*pos+len]).unwrap();
            *pos += len;
            labels.push(lbl);
        }
    }

    Ok(labels)
}

fn parse_question<'a>(
    data: &'a [u8],
    pos: &mut usize
) -> Result<'a, Question<'a>> {
    let labels = parse_labels(data, pos, &mut HashSet::new())?;

    let qtype = read_u16(data, pos);
    let qtype = Qtype::from_u16(qtype).unwrap();

    let qclass = read_u16(data, pos);
    let qclass = Qclass::from_u16(qclass).unwrap();

    Ok(Question::new(labels, qtype, qclass))
}

fn  questions<'a>(
    data: &'a [u8],
    pos: &mut usize
) -> Result<'a, Vec<Question<'a>>> {
    let mut questions = vec![];

    for _ in 0..qdcount(data) {
        questions.push(parse_question(data, pos)?);
    }

    Ok(questions)
}

fn parse_answer<'a>(
    data: &'a [u8],
    pos: &mut usize
) -> Result<'a, Record<'a>> {
    let labels = parse_labels(data, pos, &mut HashSet::new())?;
    let typ = read_u16(data, pos);
    let typ = Type::from_u16(typ)
        .ok_or(Error::new(DnsMsgError::InvalidData, format!("Invalid type: {}", typ)))?;
    let class = read_u16(data, pos);
    let class = Class::from_u16(class)
        .ok_or(Error::new(DnsMsgError::InvalidData, format!("Invalid class: {}", class)))?;
    let ttl = read_u32(data, pos);
    let len = read_u16(data, pos);

    if typ != Type::A {
        panic!("Record type not supported: {:?}", typ);
    }

    if typ == Type::A && len != 4 {
        return Err(Error::new(DnsMsgError::InvalidData, format!("Length of {} is invalid for type A", len)));
    }

    let ip = Ipv4Addr::from(read_u32(data, pos));

    Ok(Record::new(labels, class, ttl, RecordPayload::A(ip)))
}

fn answers<'a>(
    data: &'a [u8],
    pos: &mut usize
) -> Result<'a, Vec<Record<'a>>> {
    let mut answers = vec![];

    for _ in 0..ancount(data) {
        answers.push(parse_answer(data, pos)?);
    }

    Ok(answers)
}

#[cfg(test)]
mod test {
    use super::*;
    use ::labels::encode_labels;
    use ::utils::{write_u16, write_u32};
    use std::collections::HashMap;

    #[test]
    fn should_read_id() {
        let buffer = [0u8; 512];
        let result = parse(&buffer).unwrap();
        assert_eq!(0u16, result.id());

        let mut buffer = [0u8; 512];
        buffer[1] = 1;
        buffer[0] = 1;
        let result = parse(&buffer).unwrap();
        assert_eq!(0x0101u16, result.id());
    }

    #[test]
    fn should_read_qr() {
        let mut buffer = [0u8; 512];
        buffer[0] = 0xff;
        buffer[1] = 0xff;

        let result = parse(&buffer).unwrap();
        assert_eq!(QR::QUERY, result.qr());

        let mut buffer = buffer.clone();
        buffer[2] = 0b_1000_0000;
        let result = parse(&buffer).unwrap();
        assert_eq!(QR::RESPONSE, result.qr());
    }

    #[test]
    fn should_read_authoritative_answer() {
        let mut buffer = [0u8; 512];

        {
            let result = parse(&buffer).unwrap();
            assert_eq!(false, result.aa());
        }

        buffer[2] = 0b_0000_0100;
        let result = parse(&buffer).unwrap();
        assert_eq!(true, result.aa());
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
        {
            let result = parse(&buffer).unwrap();
            assert_eq!(OPCODE::QUERY, result.opcode());
        }

        buffer[2] = 1 << 3;
        {
            let result = parse(&buffer).unwrap();
            assert_eq!(OPCODE::IQUERY, result.opcode());
        }

        buffer[2] = 2 << 3;
        {
            let result = parse(&buffer).unwrap();
            assert_eq!(OPCODE::STATUS, result.opcode());
        }

        for i in 3..16 {
            buffer[2] = i << 3;
            let result = parse(&buffer);
            let msg = format!("Unknown opcode {}", i);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, msg)), result);
        }
    }

    #[test]
    fn should_read_truncated_message() {
        let mut buffer = [0u8; 512];

        {
            let result = parse(&buffer).unwrap();
            assert_eq!(false, result.tc());
        }

        buffer[2] = 0b_0000_0010;
        let result = parse(&buffer).unwrap();
        assert_eq!(true, result.tc());
    }

    #[test]
    fn should_read_recursion_desired() {
        let mut buffer = [0u8; 512];

        {
            let result = parse(&buffer).unwrap();
            assert_eq!(false, result.rd());
        }

        buffer[2] = 1;
        let result = parse(&buffer).unwrap();
        assert_eq!(true, result.rd());
    }

    #[test]
    fn should_read_recursion_available() {
        let mut buffer = [0u8; 512];

        {
            let result = parse(&buffer).unwrap();
            assert_eq!(false, result.ra());
        }

        buffer[3] = 0b_1000_0000;
        let result = parse(&buffer).unwrap();
        assert_eq!(true, result.ra());
    }

    #[test]
    fn should_read_dnssec_bits() {
        let mut buffer = [0u8; 512];

        for i in 0..9 {
            buffer[3] = i << 4;
            let result = parse(&buffer).unwrap();
            assert_eq!(i, result.dnssec());
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
            let result = parse(&buffer).unwrap();
            assert_eq!(val, result.rcode());
        }
        for i in 6..16 {
            buffer[3] = i;
            let result = parse(&buffer);
            let msg = format!("Unknown rcode value {}", i);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, msg)), result);
        }
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

        let result = parse(&buffer).unwrap();
        assert_eq!(vec![expected], result.questions());
    }

    #[test]
    fn should_read_multiple_questions() {
        let mut buffer = [0u8; 512];
        buffer[5] = 2; // 2 questions

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["www", "google", "com"]);
        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

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

        let result = parse(&buffer).unwrap();
        assert_eq!(expected, result.questions());
    }

    #[test]
    fn should_read_questions_with_label_refs() {
        let mut buffer = [0u8; 64];
        buffer[5] = 2; // 2 questions

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["google", "com"]);

        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

        write_u16(&mut buffer, &mut pos, 0xc000 | 12); // ref 12
        write_u16(&mut buffer, &mut pos, Qtype::NS as u16);
        write_u16(&mut buffer, &mut pos, Qclass::CH as u16);

        let expected = vec![
            Question::new(
                vec!["google", "com"],
                Qtype::A,
                Qclass::IN
            ),
            Question::new(
                vec!["google", "com"],
                Qtype::NS,
                Qclass::CH
            )
        ];

        let result = parse(&buffer).unwrap();
        assert_eq!(expected, result.questions());
    }

    #[test]
    fn should_recognize_cyclic_label_refs() {
        let mut buffer = [0u8; 512];
        buffer[5] = 2; // 2 questions

        buffer[12] = 0xc0;
        let mut pos = 14;
        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

        buffer[13] = pos as u8;
        buffer[pos] = 0xc0;
        buffer[pos + 1] = 12;
        pos += 2;
        write_u16(&mut buffer, &mut pos, Qtype::A as u16);
        write_u16(&mut buffer, &mut pos, Qclass::IN as u16);

        let result = parse(&buffer);
        let expected = Err(Error::new(DnsMsgError::CyclicLabelRef, "Encountered cyclic label reference at index 14"));
        assert_eq!(expected, result);
    }

    #[test]
    fn should_read_arecord_answers() {
        let mut buffer = [0u8; 512];
        write_u16(&mut buffer, &mut 6, 1);

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["google", "com"]);
        write_u16(&mut buffer, &mut pos, Type::A as u16);
        write_u16(&mut buffer, &mut pos, Class::IN as u16);
        write_u32(&mut buffer, &mut pos, 32); // TTL
        write_u16(&mut buffer, &mut pos, 4); // len

        buffer[pos..pos+4].copy_from_slice(&[8, 16, 32, 64]); // IP

        let result = parse(&buffer).unwrap();
        let expectation = Record::new(
            vec!["google", "com"],
            Class::IN,
            32,
            RecordPayload::A(Ipv4Addr::new(8, 16, 32, 64))
        );

        assert_eq!(vec![expectation], result.answers());
    }

    #[test]
    fn should_fail_on_invalid_arecord_data() {
        let mut buffer = [0u8; 128];
        write_u16(&mut buffer, &mut 6, 1);

        let mut pos = 12;
        encode_labels(&mut buffer, &mut pos, &mut HashMap::new(), vec!["google", "com"]);

        {
            write_u16(&mut buffer, &mut pos, 18);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, "Invalid type: 18")), parse(&buffer));
        }

        {
            pos -= 2;
            write_u16(&mut buffer, &mut pos, Type::A as u16);
            write_u16(&mut buffer, &mut pos, 5);
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, "Invalid class: 5")), parse(&buffer));
        }

        {
            pos -= 2;
            write_u16(&mut buffer, &mut pos, Class::IN as u16);
            write_u32(&mut buffer, &mut pos, 32); // TTL
            write_u16(&mut buffer, &mut pos, 5); // len
            assert_eq!(Err(Error::new(DnsMsgError::InvalidData, "Length of 5 is invalid for type A")), parse(&buffer));
        }
    }
}
