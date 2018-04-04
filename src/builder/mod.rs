use rand::{Rng, thread_rng};
use ::enums::*;

#[derive(Debug)]
pub struct DnsMessageBuilder {
    id: u16,
    qr: QR,
    opcode: OPCODE,
    aa: bool,
    rd: bool,
    ra: bool,
    z: u8,
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        DnsMessageBuilder {
            id: thread_rng().gen(),
            qr: QR::QUERY,
            opcode: OPCODE::QUERY,
            aa: false,
            rd: false,
            ra: false,
            z: 0,
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

    pub fn build(self) -> [u8; 512] {
        let mut buffer = [0u8; 512];

        write_u16(&mut buffer, 0, self.id);

        buffer[2] = (self.qr as u8) << 7;
        buffer[2] |= (self.opcode as u8) << 3;
        buffer[2] |= (self.aa as u8) << 2;
        // TODO: set truncated message bit
        buffer[2] |= self.rd as u8;

        buffer[3] = (self.ra as u8) << 7;
        buffer[3] |= self.z << 4;

        buffer
    }
}

fn write_u16(target: &mut[u8], pos: usize, val: u16) {
    assert!(pos < target.len() - 2, "array index out of bounds!");

    let tmp = &target[pos] as *const u8;
    let tmp = tmp as *mut u16;
    unsafe {
        *tmp = val.to_be();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::DnsRecord;

    #[test]
    fn should_init_with_default_id() {
        use std::collections::HashSet;

        let num_tests = 5;
        let mut ids = HashSet::new();

        for _ in 0..num_tests {
            let buffer = DnsMessageBuilder::new().build();
            let rec = DnsRecord::new(buffer);
            ids.insert(rec.id());
        }

        assert_eq!(num_tests, ids.len());
    }

    #[test]
    fn should_allow_id_override() {
        let buffer = DnsMessageBuilder::new()
            .with_id(5)
            .build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(5, rec.id());
    }

    #[test]
    fn should_default_to_query() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(QR::QUERY, rec.qr());
    }

    #[test]
    fn should_allow_qr_override() {
        let buffer = DnsMessageBuilder::new()
            .with_qr(QR::RESPONSE)
            .build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(QR::RESPONSE, rec.qr());
    }

    #[test]
    fn should_default_to_query_opcode() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(Ok(OPCODE::QUERY), rec.opcode());
    }

    #[test]
    fn should_allow_opcode_override() {
        let buffer = DnsMessageBuilder::new()
            .with_opcode(OPCODE::IQUERY)
            .build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(QR::QUERY, rec.qr());
        assert_eq!(Ok(OPCODE::IQUERY), rec.opcode());
    }

    #[test]
    fn should_default_to_non_authoritative_answer() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.aa());
    }

    #[test]
    fn should_allow_aa_override() {
        let buffer = DnsMessageBuilder::new()
            .with_aa(true)
            .build();
        let rec = DnsRecord::new(buffer);
        assert!(rec.aa());
    }

    #[test]
    fn should_default_to_non_truncated_message() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.tc());
    }

    #[test]
    fn should_default_to_no_recursion_desired() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.rd());
    }

    #[test]
    fn should_allow_setting_recursion_desired() {
        let buffer = DnsMessageBuilder::new()
            .with_rd(true)
            .build();
        let rec = DnsRecord::new(buffer);
        assert!(rec.rd());
    }

    #[test]
    fn should_default_to_no_recursion_available() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(false, rec.ra());
    }

    #[test]
    fn should_allow_setting_recursion_avaiable() {
        let buffer = DnsMessageBuilder::new()
            .with_ra(true)
            .build();
        let rec = DnsRecord::new(buffer);
        assert!(rec.ra());
    }

    #[test]
    fn should_default_to_zeroed_dnssec_bits() {
        let buffer = DnsMessageBuilder::new().build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(0, rec.dnssec_bits() & 0b_0111_0000);
    }

    #[test]
    fn should_allow_setting_dnssec_bits() {
        let buffer = DnsMessageBuilder::new()
            .with_dnssec_bits(0xff)
            .build();
        let rec = DnsRecord::new(buffer);
        assert_eq!(0b_0000_0111, rec.dnssec_bits());
    }
}
