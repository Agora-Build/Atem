/* Minimal native consumer of atem_core.h: builds the published vector,
 * decodes it, verifies it, and checks error and ownership rules. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atem_core.h"

#define APP_ID "970CA35de60c44645bbae8a215061b33"
#define CERT "5CFd2fd1755d40ecb72977518be15d3b"
#define VECTOR "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM="

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

int main(void) {
    CHECK(atem_core_abi_version() == ATEM_CORE_ABI_VERSION);
    CHECK(strlen(atem_core_version()) > 0);

    AtemCoreRtcTokenParams p;
    memset(&p, 0, sizeof p);
    p.struct_size = sizeof p;
    p.app_id = APP_ID;
    p.app_certificate = CERT;
    p.channel = "7d72365eb983485397e3e3f9d460bdda";
    p.uid = 2882341273u;
    p.role = ATEM_CORE_ROLE_SUBSCRIBER;
    p.token_expire = 600;
    p.privilege_expire = 600;
    p.issued_at = 1111111;
    p.salt = 1;

    char *token = NULL, *error = NULL;
    CHECK(atem_core_build_rtc_token(&p, &token, &error) == ATEM_CORE_OK);
    CHECK(error == NULL);
    CHECK(token != NULL && strcmp(token, VECTOR) == 0);

    char *json = NULL;
    CHECK(atem_core_decode_token(token, &json, &error) == ATEM_CORE_OK);
    CHECK(json != NULL && strstr(json, "\"app_id\":\"" APP_ID "\"") != NULL);

    int32_t valid = -1;
    CHECK(atem_core_verify_token_signature(token, CERT, &valid, &error) == ATEM_CORE_OK);
    CHECK(valid == 1);
    atem_core_string_free(json);
    atem_core_string_free(token);

    /* An error: outputs NULL, message set, no certificate in it. */
    p.app_id = "not-hex";
    token = NULL;
    CHECK(atem_core_build_rtc_token(&p, &token, &error) == ATEM_CORE_ERR_INVALID_APP_ID);
    CHECK(token == NULL);
    CHECK(error != NULL && strstr(error, CERT) == NULL);
    atem_core_string_free(error);

    /* Wrong struct size, NULL arguments. */
    p.app_id = APP_ID;
    p.struct_size = sizeof p - 4;
    CHECK(atem_core_build_rtc_token(&p, &token, NULL) == ATEM_CORE_ERR_STRUCT_SIZE);
    CHECK(atem_core_decode_token(NULL, &json, NULL) == ATEM_CORE_ERR_NULL_ARGUMENT);
    atem_core_string_free(NULL);

    AtemCoreRtmTokenParams r;
    memset(&r, 0, sizeof r);
    r.struct_size = sizeof r;
    r.app_id = APP_ID;
    r.app_certificate = CERT;
    r.user_id = "atem01";
    r.expire = 3600;
    CHECK(atem_core_build_rtm_token(&r, &token, &error) == ATEM_CORE_OK);
    CHECK(token != NULL && strncmp(token, "007", 3) == 0);
    atem_core_string_free(token);

    if (failures) return 1;
    printf("atem_core C consumer: ok (abi %u, %s)\n", atem_core_abi_version(), atem_core_version());
    return 0;
}
