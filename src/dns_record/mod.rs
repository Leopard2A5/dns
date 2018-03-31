use std::result;
use std::borrow::Cow;

#[derive(Debug, PartialEq, Eq)]
pub enum DnsMsgError {
    InvalidData,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Error<'a> {
    pub kind: DnsMsgError,
    pub msg:Cow<'a, str>
}

impl<'a> Error<'a> {
    pub fn new<M>(kind: DnsMsgError, msg: M) -> Self
    where M: Into<Cow<'a, str>> {
        Self {
            kind,
            msg: msg.into()
        }
    }
}

pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct DnsRecord {
    data: [u8; 512]
}

impl DnsRecord {
    pub fn new(data: [u8; 512]) -> Self {
        DnsRecord { data }
    }

    pub fn id(&self) -> u16 {
        let tmp = &self.data[0] as *const u8;
        unsafe {
            *(tmp as *const u16) 
        }
    }

    pub fn qr(&self) -> QR {
        if self.data[2] & 0xa0 == 0 {
            QR::QUERY
        } else {
            QR::RESPONSE
        }
    }

    pub fn opcode(&self) -> Result<OPCODE> {
        match self.data[2] >> 3 & 0x0f {
            0 => Ok(OPCODE::QUERY),
            1 => Ok(OPCODE::IQUERY),
            2 => Ok(OPCODE::STATUS),
            x => Err(Error::new(DnsMsgError::InvalidData, format!("Unknown opcode {}", x)))
        }
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
}

#[derive(Debug, PartialEq, Eq)]
pub enum QR {
    QUERY,
    RESPONSE
}

#[derive(Debug, PartialEq, Eq)]
pub enum OPCODE {
    QUERY,
    IQUERY,
    STATUS
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
}
