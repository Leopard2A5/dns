use std::collections::HashMap;

pub fn encode_labels<'a>(
    encoded_labels: &mut HashMap<&'a str, usize>,
    pos: usize,
    address: &'a str
) -> Vec<u8> {
    let mut ret: Vec<u8> = vec![];

    if encoded_labels.contains_key(address) {
        let jump_addr = encoded_labels.get(address).unwrap();
        ret.push(0xc0);
        ret.push(*jump_addr as u8);
    } else {
        encoded_labels.insert(address, pos);
        for label in address.split('.') {
            ret.push(label.as_bytes().len() as u8);
            ret.extend(label.as_bytes());
        }
        ret.push(0);
    }

    ret
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_labels_should_prepend_byte_length() {
        assert_eq!(4, encode_labels(&mut HashMap::new(), 0, "abcd")[0]);
        assert_eq!(3, encode_labels(&mut HashMap::new(), 0, "xxx")[0]);
    }

    #[test]
    fn encode_labels_should_encode_string() {
        let encoded = encode_labels(&mut HashMap::new(), 0, "abcd.aao");
        assert_eq!(&encoded, &[4, 97, 98, 99, 100, 3, 97, 97, 111, 0]);
    }

    #[test]
    fn encode_label_should_add_data_to_map() {
        let mut map = HashMap::new();
        encode_labels(&mut map, 5, "aa.bb");

        assert_eq!(Some(&5usize), map.get("aa.bb"));
    }

    #[test]
    fn encode_label_should_write_ref() {
        let mut map = HashMap::new();
        map.insert("aa.bb", 5);

        let buffer = encode_labels(&mut map, 0, "aa.bb");
        assert_eq!(&buffer[0..2], &[0xc0, 5]);
    }
}
