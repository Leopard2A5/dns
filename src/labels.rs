use std::borrow::Borrow;

pub fn encode_label<T>(text: T) -> Vec<u8>
where T: Borrow<str>
{
    let mut ret = vec![];

    let bytes = text.borrow().as_bytes();

    ret.push(bytes.len() as u8);
    ret.extend(bytes.iter());

    ret
}

pub fn encode_labels<'a, T>(texts: T) -> Vec<u8>
where T: IntoIterator,
      T::Item: Borrow<str>
{
    let mut ret = texts.into_iter()
        .map(|txt| encode_label(txt.borrow()))
        .fold(vec![], |mut a, t| { a.extend(t.iter()); a });

    ret.push(0);
    ret
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_label_should_prepend_byte_length() {
        for label in vec!["abcd", "aaö"] {
            let buffer = encode_label(label);
            assert_eq!(buffer[0], label.bytes().len() as u8);
        }
    }

    #[test]
    fn encode_label_should_encode_string() {
        for label in vec!["abcd", "aaö"] {
            let buffer = encode_label(label);
            let bytes = label.as_bytes();

            assert_eq!(buffer.len() - 1, bytes.len());
            for i in 0..bytes.len() {
                assert_eq!(buffer[i+1], bytes[i]);
            }
        }
    }

    #[test]
    fn encode_labels_should_add_null_terminator() {
        let buffer = encode_labels(vec!["aaa"]);
        assert_eq!("aaa".as_bytes(), &buffer[1..4]);
        assert_eq!(0, buffer[4]);
    }
}
