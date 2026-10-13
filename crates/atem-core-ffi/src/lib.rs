//! C ABI for atem-core. The header is include/atem_core.h; keep the two in
//! step (the C consumer in CI and tests/abi.rs check the shared rules).

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use atem_core::token::{
    Issue, RtcIdentity, RtcPrivileges, RtcTokenRequest, RtmLogin, RtmTokenRequest, TokenError,
};

pub const ATEM_CORE_ABI_VERSION: u32 = 1;

pub const ATEM_CORE_OK: i32 = 0;
pub const ATEM_CORE_ERR_NULL_ARGUMENT: i32 = 1;
pub const ATEM_CORE_ERR_INVALID_UTF8: i32 = 2;
pub const ATEM_CORE_ERR_STRUCT_SIZE: i32 = 3;
pub const ATEM_CORE_ERR_INVALID_ARGUMENT: i32 = 4;
pub const ATEM_CORE_ERR_INVALID_APP_ID: i32 = 10;
pub const ATEM_CORE_ERR_INVALID_APP_CERTIFICATE: i32 = 11;
pub const ATEM_CORE_ERR_INVALID_CHANNEL: i32 = 12;
pub const ATEM_CORE_ERR_INVALID_USER_ACCOUNT: i32 = 13;
pub const ATEM_CORE_ERR_INVALID_RTM_USER_ID: i32 = 14;
pub const ATEM_CORE_ERR_INVALID_EXPIRY: i32 = 15;
pub const ATEM_CORE_ERR_UNSUPPORTED_VERSION: i32 = 20;
pub const ATEM_CORE_ERR_MALFORMED_TOKEN: i32 = 21;
pub const ATEM_CORE_ERR_INTERNAL: i32 = 99;

pub const ATEM_CORE_ROLE_EXPLICIT: u32 = 0;
pub const ATEM_CORE_ROLE_PUBLISHER: u32 = 1;
pub const ATEM_CORE_ROLE_SUBSCRIBER: u32 = 2;

#[repr(C)]
pub struct AtemCoreRtcTokenParams {
    pub struct_size: u32,
    pub app_id: *const c_char,
    pub app_certificate: *const c_char,
    pub channel: *const c_char,
    pub uid: u32,
    pub user_account: *const c_char,
    pub role: u32,
    pub token_expire: u32,
    pub privilege_expire: u32,
    pub join_channel_expire: u32,
    pub publish_audio_expire: u32,
    pub publish_video_expire: u32,
    pub publish_data_expire: u32,
    pub with_rtm: u32,
    pub rtm_user_id: *const c_char,
    pub rtm_expire: u32,
    pub issued_at: u32,
    pub salt: u32,
}

#[repr(C)]
pub struct AtemCoreRtmTokenParams {
    pub struct_size: u32,
    pub app_id: *const c_char,
    pub app_certificate: *const c_char,
    pub user_id: *const c_char,
    pub expire: u32,
    pub issued_at: u32,
    pub salt: u32,
}

struct Failure {
    code: i32,
    message: String,
}

impl Failure {
    fn new(code: i32, message: impl Into<String>) -> Failure {
        Failure {
            code,
            message: message.into(),
        }
    }
}

impl From<TokenError> for Failure {
    fn from(error: TokenError) -> Failure {
        let code = match &error {
            TokenError::InvalidAppId => ATEM_CORE_ERR_INVALID_APP_ID,
            TokenError::InvalidAppCertificate => ATEM_CORE_ERR_INVALID_APP_CERTIFICATE,
            TokenError::InvalidChannel(_) => ATEM_CORE_ERR_INVALID_CHANNEL,
            TokenError::InvalidUserAccount(_) => ATEM_CORE_ERR_INVALID_USER_ACCOUNT,
            TokenError::InvalidRtmUserId(_) => ATEM_CORE_ERR_INVALID_RTM_USER_ID,
            TokenError::InvalidExpiry(_) => ATEM_CORE_ERR_INVALID_EXPIRY,
            TokenError::UnsupportedVersion => ATEM_CORE_ERR_UNSUPPORTED_VERSION,
            TokenError::Malformed(_) => ATEM_CORE_ERR_MALFORMED_TOKEN,
        };
        Failure::new(code, error.to_string())
    }
}

/// A required string argument.
///
/// # Safety
/// `p` is NULL or points to a NUL-terminated string valid for `'a`.
unsafe fn arg<'a>(p: *const c_char, name: &str) -> Result<&'a str, Failure> {
    if p.is_null() {
        return Err(Failure::new(
            ATEM_CORE_ERR_NULL_ARGUMENT,
            format!("{name} is NULL"),
        ));
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Failure::new(ATEM_CORE_ERR_INVALID_UTF8, format!("{name} is not UTF-8")))
}

/// An optional string argument (NULL = absent).
///
/// # Safety
/// As for `arg`.
unsafe fn opt_arg<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, Failure> {
    if p.is_null() {
        Ok(None)
    } else {
        unsafe { arg(p, name) }.map(Some)
    }
}

fn issue(issued_at: u32, salt: u32) -> Issue {
    let base = if issued_at == 0 {
        Issue::now()
    } else {
        Issue::at(issued_at)
    };
    if salt == 0 {
        base
    } else {
        Issue {
            issued_at: base.issued_at,
            salt,
        }
    }
}

/// Runs `body` with panics caught, then writes the result to the caller's
/// pointers. Outputs are cleared first, so they are NULL on every failure.
///
/// # Safety
/// `out` and `out_error` are NULL or valid for writing one pointer.
unsafe fn deliver(
    out: *mut *mut c_char,
    out_error: *mut *mut c_char,
    body: impl FnOnce() -> Result<String, Failure>,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = std::ptr::null_mut() };
    }
    let result = if out.is_null() {
        Err(Failure::new(
            ATEM_CORE_ERR_NULL_ARGUMENT,
            "the output pointer is NULL",
        ))
    } else {
        unsafe { *out = std::ptr::null_mut() };
        catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| {
            Err(Failure::new(
                ATEM_CORE_ERR_INTERNAL,
                "internal error in atem-core",
            ))
        })
    };
    let result = result.and_then(|value| {
        CString::new(value).map_err(|_| Failure::new(ATEM_CORE_ERR_INTERNAL, "result contains NUL"))
    });
    match result {
        Ok(value) => {
            unsafe { *out = value.into_raw() };
            ATEM_CORE_OK
        }
        Err(failure) => {
            if !out_error.is_null() {
                let message = CString::new(failure.message.replace('\0', ""))
                    .unwrap_or_else(|_| CString::new("error").expect("no NUL"));
                unsafe { *out_error = message.into_raw() };
            }
            failure.code
        }
    }
}

/// Checks `struct_size` before reading any other field.
///
/// # Safety
/// `params` is NULL or points to at least a `u32`.
unsafe fn params<'a, T>(params: *const T, name: &str) -> Result<&'a T, Failure> {
    if params.is_null() {
        return Err(Failure::new(
            ATEM_CORE_ERR_NULL_ARGUMENT,
            format!("{name} is NULL"),
        ));
    }
    let size = unsafe { *(params as *const u32) } as usize;
    if size != std::mem::size_of::<T>() {
        return Err(Failure::new(
            ATEM_CORE_ERR_STRUCT_SIZE,
            format!(
                "{name}.struct_size is {size}, this library expects {}",
                std::mem::size_of::<T>()
            ),
        ));
    }
    Ok(unsafe { &*params })
}

#[unsafe(no_mangle)]
pub extern "C" fn atem_core_abi_version() -> u32 {
    ATEM_CORE_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn atem_core_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_build_rtc_token(
    params_ptr: *const AtemCoreRtcTokenParams,
    out_token: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_token, out_error, || {
            let p = params(params_ptr, "params")?;
            let identity = match opt_arg(p.user_account, "user_account")? {
                Some(account) => RtcIdentity::UserAccount(account),
                None => RtcIdentity::Uid(p.uid),
            };
            let privileges = match p.role {
                ATEM_CORE_ROLE_PUBLISHER => RtcPrivileges::Publisher {
                    expire: p.privilege_expire,
                },
                ATEM_CORE_ROLE_SUBSCRIBER => RtcPrivileges::Subscriber {
                    expire: p.privilege_expire,
                },
                ATEM_CORE_ROLE_EXPLICIT => RtcPrivileges::Explicit {
                    join: p.join_channel_expire,
                    publish_audio: p.publish_audio_expire,
                    publish_video: p.publish_video_expire,
                    publish_data: p.publish_data_expire,
                },
                other => {
                    return Err(Failure::new(
                        ATEM_CORE_ERR_INVALID_ARGUMENT,
                        format!("role {other} is not 0, 1 or 2"),
                    ));
                }
            };
            let rtm = match p.with_rtm {
                0 => None,
                1 => Some(RtmLogin {
                    user_id: opt_arg(p.rtm_user_id, "rtm_user_id")?,
                    expire: p.rtm_expire,
                }),
                other => {
                    return Err(Failure::new(
                        ATEM_CORE_ERR_INVALID_ARGUMENT,
                        format!("with_rtm {other} is not 0 or 1"),
                    ));
                }
            };
            let request = RtcTokenRequest {
                app_id: arg(p.app_id, "app_id")?,
                app_certificate: arg(p.app_certificate, "app_certificate")?,
                channel: arg(p.channel, "channel")?,
                identity,
                privileges,
                token_expire: p.token_expire,
                rtm,
            };
            Ok(atem_core::build_rtc_token(
                &request,
                issue(p.issued_at, p.salt),
            )?)
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_build_rtm_token(
    params_ptr: *const AtemCoreRtmTokenParams,
    out_token: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_token, out_error, || {
            let p = params(params_ptr, "params")?;
            let request = RtmTokenRequest {
                app_id: arg(p.app_id, "app_id")?,
                app_certificate: arg(p.app_certificate, "app_certificate")?,
                user_id: arg(p.user_id, "user_id")?,
                expire: p.expire,
            };
            Ok(atem_core::build_rtm_token(
                &request,
                issue(p.issued_at, p.salt),
            )?)
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_decode_token(
    token: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_json, out_error, || {
            let decoded = atem_core::decode_token(arg(token, "token")?)?;
            serde_json::to_string(&decoded)
                .map_err(|_| Failure::new(ATEM_CORE_ERR_INTERNAL, "could not encode JSON"))
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_verify_token_signature(
    token: *const c_char,
    app_certificate: *const c_char,
    out_valid: *mut i32,
    out_error: *mut *mut c_char,
) -> i32 {
    // Reuse `deliver` for panics, error strings and clearing; the "value" is
    // discarded and out_valid carries the answer.
    let mut scratch: *mut c_char = std::ptr::null_mut();
    let status = unsafe {
        deliver(&mut scratch, out_error, || {
            if out_valid.is_null() {
                return Err(Failure::new(
                    ATEM_CORE_ERR_NULL_ARGUMENT,
                    "out_valid is NULL",
                ));
            }
            *out_valid = 0;
            let valid = atem_core::verify_token_signature(
                arg(token, "token")?,
                arg(app_certificate, "app_certificate")?,
            )?;
            *out_valid = i32::from(valid);
            Ok(String::new())
        })
    };
    if !scratch.is_null() {
        drop(unsafe { CString::from_raw(scratch) });
    }
    status
}

/// # Safety
/// `s` is NULL or a string returned by this library, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { CString::from_raw(s) })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_inside_becomes_internal_not_an_unwind() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut c_char = std::ptr::null_mut();
        let status = unsafe { deliver(&mut out, &mut error, || panic!("boom")) };
        assert_eq!(status, ATEM_CORE_ERR_INTERNAL);
        assert!(out.is_null());
        let message = unsafe { CString::from_raw(error) }.into_string().unwrap();
        assert_eq!(message, "internal error in atem-core");
    }
}
