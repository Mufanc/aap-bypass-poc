use nix::libc::c_char;
use std::ffi::{CStr, CString};

const PROP_VALUE_MAX: usize = 92;

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> u32;
}

pub fn get(name: &str) -> Option<Box<str>> {
    let name = CString::new(name).ok()?;
    let mut buffer = [0u8; PROP_VALUE_MAX + 1];

    let len = unsafe { __system_property_get(name.as_ptr(), buffer.as_mut_ptr() as _) };

    if len == 0 {
        return None;
    }

    let value = CStr::from_bytes_until_nul(&buffer).ok()?;

    Some(value.to_string_lossy().into_owned().into_boxed_str())
}
