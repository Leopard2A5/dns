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
}

#[derive(Debug, PartialEq, Eq)]
pub enum QR {
    QUERY,
    RESPONSE
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
}
