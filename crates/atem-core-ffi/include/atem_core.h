/*
 * atem_core.h — C ABI for atem-core: Agora AccessToken2 (RTC/RTM) tokens.
 * ABI version 1. See crates/atem-core-ffi/README.md and designs/atem-core.md.
 *
 * Rules for every function:
 *  - Strings are NUL-terminated UTF-8.
 *  - Returns ATEM_CORE_OK (0) or an error code below. On success the output
 *    string is set and *out_error is NULL; on failure outputs are NULL and,
 *    if out_error is not NULL, *out_error holds a message.
 *  - Every string returned through an out-parameter is owned by the caller
 *    and must be freed exactly once with atem_core_string_free (NULL is ok).
 *  - Functions are thread-safe and keep no state. Nothing is logged; error
 *    messages never contain the App Certificate or a token.
 */
#ifndef ATEM_CORE_H
#define ATEM_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ATEM_CORE_ABI_VERSION 1u

/* Status codes. */
#define ATEM_CORE_OK                           0
#define ATEM_CORE_ERR_NULL_ARGUMENT            1
#define ATEM_CORE_ERR_INVALID_UTF8             2
#define ATEM_CORE_ERR_STRUCT_SIZE              3
#define ATEM_CORE_ERR_INVALID_ARGUMENT         4
#define ATEM_CORE_ERR_INVALID_APP_ID          10
#define ATEM_CORE_ERR_INVALID_APP_CERTIFICATE 11
#define ATEM_CORE_ERR_INVALID_CHANNEL         12
#define ATEM_CORE_ERR_INVALID_USER_ACCOUNT    13
#define ATEM_CORE_ERR_INVALID_RTM_USER_ID     14
#define ATEM_CORE_ERR_INVALID_EXPIRY          15
#define ATEM_CORE_ERR_UNSUPPORTED_VERSION     20
#define ATEM_CORE_ERR_MALFORMED_TOKEN         21
#define ATEM_CORE_ERR_INTERNAL                99

/* AtemCoreRtcTokenParams.role */
#define ATEM_CORE_ROLE_EXPLICIT   0u /* use the four *_expire privilege fields */
#define ATEM_CORE_ROLE_PUBLISHER  1u /* join + publish audio/video/data, privilege_expire */
#define ATEM_CORE_ROLE_SUBSCRIBER 2u /* join only, privilege_expire */

/* All expiries are seconds after the issue time and must be >= 1. */
typedef struct AtemCoreRtcTokenParams {
    uint32_t struct_size;          /* sizeof(AtemCoreRtcTokenParams) */
    const char *app_id;            /* 32 hex characters */
    const char *app_certificate;   /* 32 hex characters */
    const char *channel;           /* 1-64 bytes */
    uint32_t uid;                  /* used when user_account is NULL; 0 = any user */
    const char *user_account;      /* NULL, or a 1-255 byte user account (then uid is ignored) */
    uint32_t role;                 /* ATEM_CORE_ROLE_* */
    uint32_t token_expire;
    uint32_t privilege_expire;     /* PUBLISHER / SUBSCRIBER */
    uint32_t join_channel_expire;  /* EXPLICIT */
    uint32_t publish_audio_expire; /* EXPLICIT */
    uint32_t publish_video_expire; /* EXPLICIT */
    uint32_t publish_data_expire;  /* EXPLICIT */
    uint32_t with_rtm;             /* 0 or 1: also grant RTM login */
    const char *rtm_user_id;       /* NULL = reuse the RTC account; else 1-64 bytes */
    uint32_t rtm_expire;           /* when with_rtm = 1 */
    uint32_t issued_at;            /* unix seconds; 0 = now */
    uint32_t salt;                 /* 0 = random (normal use); fixed only for tests */
} AtemCoreRtcTokenParams;

typedef struct AtemCoreRtmTokenParams {
    uint32_t struct_size;          /* sizeof(AtemCoreRtmTokenParams) */
    const char *app_id;
    const char *app_certificate;
    const char *user_id;           /* 1-64 bytes */
    uint32_t expire;
    uint32_t issued_at;            /* 0 = now */
    uint32_t salt;                 /* 0 = random */
} AtemCoreRtmTokenParams;

/* ATEM_CORE_ABI_VERSION of the linked library. */
uint32_t atem_core_abi_version(void);

/* atem-core's version, e.g. "0.1.0". Static: never free it. */
const char *atem_core_version(void);

int32_t atem_core_build_rtc_token(const AtemCoreRtcTokenParams *params,
                                  char **out_token, char **out_error);

int32_t atem_core_build_rtm_token(const AtemCoreRtmTokenParams *params,
                                  char **out_token, char **out_error);

/*
 * Reads a token's fields into JSON. Does NOT establish authenticity; use
 * atem_core_verify_token_signature. JSON shape:
 * {"version":"007","app_id":"...","issued_at":1700000000,"expire":3600,
 *  "salt":123,"services":[{"service_type":1,"privileges":{"1":3600,...},
 *  "details":{"kind":"rtc","channel":"...","account":"..."}},
 *  {"service_type":2,...,"details":{"kind":"rtm","user_id":"..."}}]}
 * Other kinds: "fpa", "chat" (user_id), "apaas" (room_uuid, user_uuid, role).
 */
int32_t atem_core_decode_token(const char *token, char **out_json, char **out_error);

/* *out_valid = 1 if token was signed with app_certificate, else 0.
 * *out_valid is also 0 on any error. */
int32_t atem_core_verify_token_signature(const char *token, const char *app_certificate,
                                         int32_t *out_valid, char **out_error);

/* Frees a string returned by this library. NULL is ignored. */
void atem_core_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ATEM_CORE_H */
