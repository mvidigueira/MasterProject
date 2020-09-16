// #![no_std]
#![feature(vec_into_raw_parts)]

#[no_mangle]
pub extern "C" fn allocate_vec(length: i32) -> *mut u8 {
    let v = vec![0; length as usize];
    v.into_raw_parts().0
}

#[no_mangle]
pub extern "C" fn execute(ptr: *mut u8, length: i32) -> *mut u8 {
    let mut v: Vec<u8> = unsafe {
        Vec::from_raw_parts(ptr, length as usize, length as usize)
    };

    v[0] = v[0] + 1;
    let (ptr, len, _) = v.into_raw_parts();

    [len.to_be_bytes(), (ptr as i32).to_be_bytes()]
    .concat()
    .as_mut_ptr()
}

// #[panic_handler]
// fn handle_panic(_: &core::panic::PanicInfo) -> ! {
//     unreachable!()
// }