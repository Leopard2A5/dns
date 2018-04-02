use rand::{Rng, thread_rng};

#[derive(Debug)]
pub struct DnsMessageBuilder {
    id: u16,
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        DnsMessageBuilder {
            id: thread_rng().gen(),
        }
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn build(self) -> [u8; 512] {
        let mut buffer = [0u8; 512];

        write_u16(&mut buffer, 0, self.id);

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
}