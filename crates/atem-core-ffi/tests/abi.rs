//! The C ABI as a C caller sees it: status codes, ownership, nulls, sizes.

use atem_core_ffi::*;
use std::ffi::{CStr, CString, c_char};
use std::ptr::{null, null_mut};

const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
const VECTOR: &str = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM=";

type Edit = Box<dyn Fn(&mut AtemCoreRtcTokenParams, &mut Strings)>;

struct Strings(Vec<CString>);
impl Strings {
    fn c(&mut self, s: &str) -> *const c_char {
        self.0.push(CString::new(s).unwrap());
        self.0.last().unwrap().as_ptr()
    }
}

/// Takes ownership of a returned string (frees it through the ABI).
fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { atem_core_string_free(p) };
    Some(s)
}

/// The published vector's inputs: uid 2882341273, join only, 600 s.
fn vector_params(s: &mut Strings) -> AtemCoreRtcTokenParams {
    AtemCoreRtcTokenParams {
        struct_size: std::mem::size_of::<AtemCoreRtcTokenParams>() as u32,
        app_id: s.c(APP_ID),
        app_certificate: s.c(CERT),
        channel: s.c("7d72365eb983485397e3e3f9d460bdda"),
        uid: 2882341273,
        user_account: null(),
        role: ATEM_CORE_ROLE_SUBSCRIBER,
        token_expire: 600,
        privilege_expire: 600,
        join_channel_expire: 0,
        publish_audio_expire: 0,
        publish_video_expire: 0,
        publish_data_expire: 0,
        with_rtm: 0,
        rtm_user_id: null(),
        rtm_expire: 0,
        issued_at: 1111111,
        salt: 1,
    }
}

fn build(params: &AtemCoreRtcTokenParams) -> (i32, Option<String>, Option<String>) {
    let (mut token, mut error) = (null_mut(), null_mut());
    let status = unsafe { atem_core_build_rtc_token(params, &mut token, &mut error) };
    (status, take(token), take(error))
}

#[test]
fn reports_its_abi_and_version() {
    assert_eq!(atem_core_abi_version(), 1);
    let v = unsafe { CStr::from_ptr(atem_core_version()) }
        .to_str()
        .unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

#[test]
fn builds_the_published_vector_through_the_abi() {
    let mut s = Strings(vec![]);
    let (status, token, error) = build(&vector_params(&mut s));
    assert_eq!(
        (status, token.as_deref(), error),
        (ATEM_CORE_OK, Some(VECTOR), None)
    );
}

#[test]
fn explicit_publisher_rtm_and_user_account_variants_build() {
    let mut s = Strings(vec![]);
    let mut p = vector_params(&mut s);
    p.user_account = s.c("alice");
    p.role = ATEM_CORE_ROLE_EXPLICIT;
    p.join_channel_expire = 300;
    p.publish_audio_expire = 200;
    p.publish_video_expire = 100;
    p.publish_data_expire = 50;
    p.with_rtm = 1;
    p.rtm_user_id = s.c("bob");
    p.rtm_expire = 60;
    let (status, token, _) = build(&p);
    assert_eq!(status, ATEM_CORE_OK);
    let d = atem_core::decode_token(&token.unwrap()).unwrap();
    assert_eq!(d.services.len(), 2);
    assert_eq!(d.services[0].privileges.get(&4), Some(&50));
}

#[test]
fn validation_errors_map_to_codes_and_messages_without_secrets() {
    let mut s = Strings(vec![]);
    let cases: Vec<(Edit, i32)> = vec![
        (
            Box::new(|p, s| p.app_id = s.c("nothex")),
            ATEM_CORE_ERR_INVALID_APP_ID,
        ),
        (
            Box::new(|p, s| p.app_certificate = s.c("nothex")),
            ATEM_CORE_ERR_INVALID_APP_CERTIFICATE,
        ),
        (
            Box::new(|p, s| p.channel = s.c("")),
            ATEM_CORE_ERR_INVALID_CHANNEL,
        ),
        (
            Box::new(|p, s| p.user_account = s.c("")),
            ATEM_CORE_ERR_INVALID_USER_ACCOUNT,
        ),
        (
            Box::new(|p, _| p.token_expire = 0),
            ATEM_CORE_ERR_INVALID_EXPIRY,
        ),
        (
            Box::new(|p, _| {
                p.with_rtm = 1;
                p.rtm_expire = 60;
                p.uid = 0
            }),
            ATEM_CORE_ERR_INVALID_RTM_USER_ID,
        ),
        (Box::new(|p, _| p.role = 7), ATEM_CORE_ERR_INVALID_ARGUMENT),
        (
            Box::new(|p, _| p.with_rtm = 2),
            ATEM_CORE_ERR_INVALID_ARGUMENT,
        ),
    ];
    for (edit, code) in cases {
        let mut p = vector_params(&mut s);
        edit(&mut p, &mut s);
        let (status, token, error) = build(&p);
        assert_eq!(status, code);
        assert!(token.is_none());
        let error = error.expect("an error message");
        assert!(!error.contains(CERT), "{error}");
    }
}

#[test]
fn null_and_bad_utf8_arguments_are_errors_not_crashes() {
    let mut s = Strings(vec![]);
    let (mut token, mut error) = (null_mut(), null_mut());
    assert_eq!(
        unsafe { atem_core_build_rtc_token(null(), &mut token, &mut error) },
        ATEM_CORE_ERR_NULL_ARGUMENT
    );
    assert!(token.is_null());
    take(error);

    let p = vector_params(&mut s);
    assert_eq!(
        unsafe { atem_core_build_rtc_token(&p, null_mut(), null_mut()) },
        ATEM_CORE_ERR_NULL_ARGUMENT
    );

    let mut p = vector_params(&mut s);
    p.channel = null();
    assert_eq!(build(&p).0, ATEM_CORE_ERR_NULL_ARGUMENT);

    let bad = [0xff_u8, 0xfe, 0];
    let mut p = vector_params(&mut s);
    p.channel = bad.as_ptr().cast();
    assert_eq!(build(&p).0, ATEM_CORE_ERR_INVALID_UTF8);

    // A NULL out_error is allowed: the status still says what failed.
    let mut p = vector_params(&mut s);
    p.token_expire = 0;
    let mut token = null_mut();
    assert_eq!(
        unsafe { atem_core_build_rtc_token(&p, &mut token, null_mut()) },
        ATEM_CORE_ERR_INVALID_EXPIRY
    );
    assert!(token.is_null());
}

#[test]
fn an_unknown_struct_size_is_rejected() {
    let mut s = Strings(vec![]);
    let mut p = vector_params(&mut s);
    p.struct_size -= 4;
    assert_eq!(build(&p).0, ATEM_CORE_ERR_STRUCT_SIZE);
}

#[test]
fn rtm_tokens_build() {
    let mut s = Strings(vec![]);
    let p = AtemCoreRtmTokenParams {
        struct_size: std::mem::size_of::<AtemCoreRtmTokenParams>() as u32,
        app_id: s.c(APP_ID),
        app_certificate: s.c(CERT),
        user_id: s.c("atem01"),
        expire: 3600,
        issued_at: 0,
        salt: 0,
    };
    let (mut token, mut error) = (null_mut(), null_mut());
    assert_eq!(
        unsafe { atem_core_build_rtm_token(&p, &mut token, &mut error) },
        ATEM_CORE_OK
    );
    assert!(take(error).is_none());
    let d = atem_core::decode_token(&take(token).unwrap()).unwrap();
    assert_eq!(
        d.services[0].details,
        atem_core::ServiceDetails::Rtm {
            user_id: "atem01".into()
        }
    );
}

#[test]
fn decode_returns_json_and_errors_on_garbage() {
    let mut s = Strings(vec![]);
    let (mut json, mut error) = (null_mut(), null_mut());
    assert_eq!(
        unsafe { atem_core_decode_token(s.c(VECTOR), &mut json, &mut error) },
        ATEM_CORE_OK
    );
    let v: serde_json::Value = serde_json::from_str(&take(json).unwrap()).unwrap();
    assert_eq!(v["app_id"], APP_ID);
    assert_eq!(v["issued_at"], 1111111);
    assert_eq!(v["services"][0]["details"]["kind"], "rtc");
    assert_eq!(v["services"][0]["details"]["account"], "2882341273");
    assert_eq!(v["services"][0]["privileges"]["1"], 600);

    let (mut json, mut error2) = (null_mut(), null_mut());
    assert_eq!(
        unsafe { atem_core_decode_token(s.c("006xyz"), &mut json, &mut error2) },
        ATEM_CORE_ERR_UNSUPPORTED_VERSION
    );
    assert!(json.is_null());
    take(error2);
    let (mut json, mut error3) = (null_mut(), null_mut());
    assert_eq!(
        unsafe { atem_core_decode_token(s.c("007!!"), &mut json, &mut error3) },
        ATEM_CORE_ERR_MALFORMED_TOKEN
    );
    take(error3);
    take(error);
}

#[test]
fn verify_reports_validity_through_out_valid() {
    let mut s = Strings(vec![]);
    let mut valid = -1;
    let mut error = null_mut();
    assert_eq!(
        unsafe { atem_core_verify_token_signature(s.c(VECTOR), s.c(CERT), &mut valid, &mut error) },
        ATEM_CORE_OK
    );
    assert_eq!(valid, 1);
    assert_eq!(
        unsafe {
            atem_core_verify_token_signature(
                s.c(VECTOR),
                s.c("00000000000000000000000000000000"),
                &mut valid,
                &mut error,
            )
        },
        ATEM_CORE_OK
    );
    assert_eq!(valid, 0);
    assert_eq!(
        unsafe { atem_core_verify_token_signature(s.c(VECTOR), s.c(CERT), null_mut(), &mut error) },
        ATEM_CORE_ERR_NULL_ARGUMENT
    );
    take(error);
}

#[test]
fn freeing_null_is_a_no_op() {
    unsafe { atem_core_string_free(null_mut()) };
}

#[test]
fn rust_struct_sizes_match_the_c_layout() {
    // 5 pointers + 13 u32 fields on 64-bit targets, padded to pointer alignment.
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(std::mem::size_of::<AtemCoreRtcTokenParams>(), 104);
        assert_eq!(std::mem::size_of::<AtemCoreRtmTokenParams>(), 48);
    }
}
