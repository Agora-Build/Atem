#include "atem_rtm.h"

#include <stdlib.h>
#include <string.h>

#include <mutex>
#include <string>

struct AtemRtmClient {
    AtemRtmConfig config{};
    AtemRtmMessageCallback callback{nullptr};
    void* user_data{nullptr};
    bool connected{false};
    bool logged_in{false};
    bool channel_joined{false};
    std::string user_id;
    std::string channel_id;
    std::string token;
};

namespace {

inline std::string copy_or_empty(const char* value) {
    return value ? std::string(value) : std::string();
}

} // namespace

extern "C" {

AtemRtmClient* atem_rtm_create(
    const AtemRtmConfig* config,
    AtemRtmMessageCallback callback,
    void* user_data) {
    if (!config) {
        return nullptr;
    }
    auto* client = new AtemRtmClient();
    client->config = *config;
    client->callback = callback;
    client->user_data = user_data;
    client->connected = false;
    return client;
}

void atem_rtm_destroy(AtemRtmClient* client) {
    if (!client) {
        return;
    }
    delete client;
}

int atem_rtm_connect(AtemRtmClient* client) {
    if (!client) {
        return -1;
    }
    client->connected = true;
    client->logged_in = false;
    client->channel_joined = false;
    return 0;
}

int atem_rtm_disconnect(AtemRtmClient* client) {
    if (!client) {
        return -1;
    }
    client->connected = false;
    client->logged_in = false;
    client->channel_joined = false;
    return 0;
}

int atem_rtm_login(
    AtemRtmClient* client,
    const char* token,
    const char* user_id) {
    if (!client || !client->connected || !user_id) {
        return -1;
    }
    client->token = token ? token : "";
    client->user_id = user_id;
    client->logged_in = true;
    return 0;
}

int atem_rtm_join_channel(
    AtemRtmClient* client,
    const char* channel_id) {
    if (!client || !client->logged_in || !channel_id) {
        return -1;
    }
    client->channel_id = channel_id;
    client->channel_joined = true;
    return 0;
}

int atem_rtm_publish_channel(
    AtemRtmClient* client,
    const char* payload) {
    if (!client || !client->connected || !client->channel_joined || !payload) {
        return -1;
    }
    if (client->callback) {
        client->callback(client->config.client_id ? client->config.client_id : "self", payload, client->user_data);
    }
    return 0;
}

int atem_rtm_send_peer(
    AtemRtmClient* client,
    const char* target_client_id,
    const char* payload) {
    if (!client || !client->connected || !target_client_id || !payload) {
        return -1;
    }
    if (client->callback) {
        // Stub: immediately echo back to simulate delivery.
        client->callback(target_client_id, payload, client->user_data);
    }
    return 0;
}

} // extern "C"
