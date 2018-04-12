use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use ::utils::write_u16;

pub fn encode_label<'a, T>(
    target: &mut [u8],
    pos: &mut usize,
    encoded_labels: &mut HashMap<Cow<'a, str>, usize>,
    text: T
)
where T: Into<Cow<'a, str>>
{
    let initial_pos = *pos;
    let text = text.into();

    if let Some(prior_pos) = encoded_labels.get(&text) {
        let jump = 0xc000 ^ (*prior_pos) as u16;
        write_u16(target, pos, jump);
        return;
    }

    {
        let string: &str = text.borrow();
        let bytes = string.as_bytes();
        let len = bytes.len();

        target[*pos] = len as u8;
        *pos += 1;
        target[*pos..*pos+len].copy_from_slice(bytes);
        *pos += len;
    }

    encoded_labels.insert(text, initial_pos);
}

pub fn encode_labels<'a, T>(
    target: &mut [u8],
    pos: &mut usize,
    mut encoded_labels: &mut HashMap<Cow<'a, str>, usize>,
    texts: T
)
where T: IntoIterator,
      T::Item: Into<Cow<'a, str>>
{
    for text in texts {
        encode_label(target, pos, &mut encoded_labels, text);
    }
    target[*pos] = 0;
    *pos += 1;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_label_should_prepend_byte_length() {
        for label in vec!["abcd", "aaö"] {
            let mut buffer = [0u8; 10];
            encode_label(&mut buffer, &mut 0, &mut HashMap::new(), label);
            assert_eq!(buffer[0], label.bytes().len() as u8);
        }
    }

    #[test]
    fn encode_label_should_encode_string() {
        for label in vec!["abcd", "aaö"] {
            let mut buffer = [0u8; 10];
            encode_label(&mut buffer, &mut 0, &mut HashMap::new(), label);
            let bytes = label.as_bytes();

            for i in 0..bytes.len() {
                assert_eq!(buffer[i+1], bytes[i]);
            }
        }
    }

    #[test]
    fn encode_labels_should_add_null_terminator() {
        let mut buffer = [0u8; 5];
        encode_labels(&mut buffer, &mut 0, &mut HashMap::new(), vec!["aaa"]);
        assert_eq!("aaa".as_bytes(), &buffer[1..4]);
        assert_eq!(0, buffer[4]);
    }

    #[test]
    fn encode_label_should_add_data_to_map() {
        let mut buffer = [0u8; 20];
        let mut map = HashMap::new();
        encode_label(&mut buffer, &mut 5, &mut map, "aa");

        assert_eq!(Some(&5usize), map.get("aa"));
    }

    #[test]
    fn encode_label_should_write_ref() {
        let mut buffer = [0u8; 20];
        let mut map = HashMap::new();
        map.insert(Cow::Borrowed("aa"), 5);

        encode_label(&mut buffer, &mut 2, &mut map, "aa");
        assert_eq!(&buffer[2..4], &[0xc0, 5]);
    }
}
