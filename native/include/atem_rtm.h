#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AtemRtmClient AtemRtmClient;

typedef struct {
    const char* app_id;
    const char* token;
    const char* channel;
    const char* client_id;
} AtemRtmConfig;

typedef void (*AtemRtmMessageCallback)(
    const char* from_client_id,
    const char* payload,
    void* user_data);

AtemRtmClient* atem_rtm_create(
    const AtemRtmConfig* config,
    AtemRtmMessageCallback callback,
    void* user_data);

void atem_rtm_destroy(AtemRtmClient* client);

int atem_rtm_connect(AtemRtmClient* client);
int atem_rtm_disconnect(AtemRtmClient* client);

int atem_rtm_publish_channel(
    AtemRtmClient* client,
    const char* payload);

int atem_rtm_send_peer(
    AtemRtmClient* client,
    const char* target_client_id,
    const char* payload);

#ifdef __cplusplus
}
#endif

