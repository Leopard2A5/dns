use std::borrow::Borrow;

pub fn encode_label<T>(
    target: &mut [u8],
    pos: &mut usize,
    text: T
)
where T: Borrow<str>
{
    let bytes = text.borrow().as_bytes();

    target[*pos] = bytes.len() as u8;
    *pos += 1;

    target[*pos..*pos+bytes.len()].copy_from_slice(bytes);
    *pos += bytes.len();
}

pub fn encode_labels<'a, T>(
    target: &mut [u8],
    pos: &mut usize,
    texts: T
)
where T: IntoIterator,
      T::Item: Borrow<str>
{
    for text in texts {
        encode_label(target, pos, text);
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
            encode_label(&mut buffer, &mut 0, label);
            assert_eq!(buffer[0], label.bytes().len() as u8);
        }
    }

    #[test]
    fn encode_label_should_encode_string() {
        for label in vec!["abcd", "aaö"] {
            let mut buffer = [0u8; 10];
            encode_label(&mut buffer, &mut 0, label);
            let bytes = label.as_bytes();

            for i in 0..bytes.len() {
                assert_eq!(buffer[i+1], bytes[i]);
            }
        }
    }

    #[test]
    fn encode_labels_should_add_null_terminator() {
        let mut buffer = [0u8; 5];
        encode_labels(&mut buffer, &mut 0, vec!["aaa"]);
        assert_eq!("aaa".as_bytes(), &buffer[1..4]);
        assert_eq!(0, buffer[4]);
    }
}
