use anyhow::anyhow;
use nix::libc::{c_char, pid_t};
use std::ffi::{CStr, CString};

const PROP_VALUE_MAX: usize = 92;

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> u32;
}

fn get(name: &str) -> Option<Box<str>> {
    let name = CString::new(name).ok()?;
    let mut buffer = [0u8; PROP_VALUE_MAX + 1];

    let len = unsafe { __system_property_get(name.as_ptr(), buffer.as_mut_ptr() as _) };

    if len == 0 {
        return None;
    }

    let value = CStr::from_bytes_until_nul(&buffer).ok()?;

    Some(value.to_string_lossy().into_owned().into_boxed_str())
}

pub fn find_audio_server() -> anyhow::Result<pid_t> {
    get("init.svc_debug_pid.audioserver")
        .ok_or_else(|| anyhow!("failed to read property"))
        .and_then(|value| {
            value
                .parse::<i32>()
                .map_err(|err| anyhow!("failed to parse pid: {err}"))
        })
}

pub fn api_version() -> anyhow::Result<u32> {
    let api: u32 = get("ro.build.version.sdk")
        .ok_or_else(|| anyhow!("failed to read ro.build.version.sdk"))?
        .parse()
        .map_err(|err| anyhow!("failed to parse API version: {err}"))?;

    let preview: u32 = get("ro.build.version.preview_sdk")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(api + preview)
}
