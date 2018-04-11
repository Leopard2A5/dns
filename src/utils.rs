pub fn write_u16(target: &mut[u8], pos: &mut usize, val: u16) {
    assert!(*pos < target.len() - 2, "array index out of bounds!");

    let tmp = &target[*pos] as *const u8;
    let tmp = tmp as *mut u16;
    unsafe {
        *tmp = val.to_be();
    }
    *pos += 2;
}
