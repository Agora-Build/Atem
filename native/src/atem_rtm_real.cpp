// Real Agora RTM 2.x SDK integration
// This file is compiled only when the `real_rtm` Cargo feature is enabled.

#include "atem_rtm.h"

#include "IAgoraRtmClient.h"
#include "AgoraRtmBase.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

// ---------------------------------------------------------------------------
// Internal state wrapped behind the opaque AtemRtmClient pointer
// ---------------------------------------------------------------------------

struct AtemRtmClient : public agora::rtm::IRtmEventHandler {
    // Agora SDK client handle (owned)
    agora::rtm::IRtmClient* rtm_client{nullptr};

    // User-provided callback + context
    AtemRtmMessageCallback callback{nullptr};
    void* user_data{nullptr};

    // Config copies kept for lifetime management
    std::string app_id;
    std::string token;
    std::string channel;
    std::string client_id;

    // Guard for callback invocations from SDK threads
    std::mutex mtx;

    // -----------------------------------------------------------------------
    // IRtmEventHandler overrides
    // -----------------------------------------------------------------------

    void onMessageEvent(const MessageEvent& event) override {
        std::lock_guard<std::mutex> lock(mtx);
        if (!callback) return;

        const char* sender = event.publisher ? event.publisher : "";
        // For string messages the payload is a null-terminated string.
        // For binary messages we still forward the pointer; the Rust side
        // interprets it via the length in RtmEvent.
        const char* payload = event.message ? event.message : "";

        callback(sender, payload, user_data);
    }

    void onPresenceEvent(const PresenceEvent& event) override {
        (void)event;
        fprintf(stderr, "[atem_rtm_real] onPresenceEvent type=%d channel=%s\n",
                event.type, event.channelName ? event.channelName : "(null)");
    }

    void onTopicEvent(const TopicEvent& event) override {
        (void)event;
        fprintf(stderr, "[atem_rtm_real] onTopicEvent type=%d channel=%s\n",
                event.type, event.channelName ? event.channelName : "(null)");
    }

    void onLockEvent(const LockEvent& event) override {
        (void)event;
        fprintf(stderr, "[atem_rtm_real] onLockEvent type=%d channel=%s\n",
                event.eventType, event.channelName ? event.channelName : "(null)");
    }

    void onStorageEvent(const StorageEvent& event) override {
        (void)event;
        fprintf(stderr, "[atem_rtm_real] onStorageEvent type=%d target=%s\n",
                event.eventType, event.target ? event.target : "(null)");
    }

    void onLinkStateEvent(const LinkStateEvent& event) override {
        fprintf(stderr,
                "[atem_rtm_real] onLinkStateEvent prev=%d cur=%d service=%d reason=%d\n",
                event.previousState, event.currentState,
                event.serviceType, event.reasonCode);
    }

    void onConnectionStateChanged(const char* channelName,
                                  agora::rtm::RTM_CONNECTION_STATE state,
                                  agora::rtm::RTM_CONNECTION_CHANGE_REASON reason) override {
        fprintf(stderr,
                "[atem_rtm_real] onConnectionStateChanged channel=%s state=%d reason=%d\n",
                channelName ? channelName : "(null)", state, reason);
    }

    void onTokenPrivilegeWillExpire(const char* channelName) override {
        fprintf(stderr,
                "[atem_rtm_real] WARNING: token will expire soon (channel=%s)\n",
                channelName ? channelName : "(null)");
    }

    void onLoginResult(const uint64_t requestId, agora::rtm::RTM_ERROR_CODE errorCode) override {
        fprintf(stderr,
                "[atem_rtm_real] onLoginResult requestId=%llu errorCode=%d\n",
                (unsigned long long)requestId, errorCode);
    }

    void onLogoutResult(const uint64_t requestId, agora::rtm::RTM_ERROR_CODE errorCode) override {
        fprintf(stderr,
                "[atem_rtm_real] onLogoutResult requestId=%llu errorCode=%d\n",
                (unsigned long long)requestId, errorCode);
    }

    void onSubscribeResult(const uint64_t requestId, const char* channelName,
                           agora::rtm::RTM_ERROR_CODE errorCode) override {
        fprintf(stderr,
                "[atem_rtm_real] onSubscribeResult requestId=%llu channel=%s errorCode=%d\n",
                (unsigned long long)requestId,
                channelName ? channelName : "(null)", errorCode);
    }

    void onPublishResult(const uint64_t requestId, agora::rtm::RTM_ERROR_CODE errorCode) override {
        fprintf(stderr,
                "[atem_rtm_real] onPublishResult requestId=%llu errorCode=%d\n",
                (unsigned long long)requestId, errorCode);
    }

    void onRenewTokenResult(const uint64_t requestId,
                            agora::rtm::RTM_SERVICE_TYPE serverType,
                            const char* channelName,
                            agora::rtm::RTM_ERROR_CODE errorCode) override {
        fprintf(stderr,
                "[atem_rtm_real] onRenewTokenResult requestId=%llu serviceType=%d channel=%s errorCode=%d\n",
                (unsigned long long)requestId, serverType,
                channelName ? channelName : "(null)", errorCode);
    }
};

// ---------------------------------------------------------------------------
// C API implementation
// ---------------------------------------------------------------------------

extern "C" {

AtemRtmClient* atem_rtm_create(
    const AtemRtmConfig* config,
    AtemRtmMessageCallback callback,
    void* user_data) {
    if (!config || !config->app_id || !config->client_id) {
        fprintf(stderr, "[atem_rtm_real] atem_rtm_create: invalid config\n");
        return nullptr;
    }

    auto* client = new AtemRtmClient();
    client->callback = callback;
    client->user_data = user_data;
    client->app_id = config->app_id;
    client->token = config->token ? config->token : "";
    client->channel = config->channel ? config->channel : "";
    client->client_id = config->client_id;

    // Build Agora RtmConfig
    agora::rtm::RtmConfig rtm_cfg;
    rtm_cfg.appId = client->app_id.c_str();
    rtm_cfg.userId = client->client_id.c_str();
    rtm_cfg.eventHandler = client;  // AtemRtmClient inherits IRtmEventHandler

    int error_code = 0;
    client->rtm_client = agora::rtm::createAgoraRtmClient(rtm_cfg, error_code);
    if (!client->rtm_client || error_code != 0) {
        fprintf(stderr,
                "[atem_rtm_real] createAgoraRtmClient failed: errorCode=%d\n",
                error_code);
        delete client;
        return nullptr;
    }

    fprintf(stderr, "[atem_rtm_real] RTM client created (appId=%.8s... userId=%s)\n",
            client->app_id.c_str(), client->client_id.c_str());
    return client;
}

void atem_rtm_destroy(AtemRtmClient* client) {
    if (!client) return;

    if (client->rtm_client) {
        client->rtm_client->release();
        client->rtm_client = nullptr;
    }
    delete client;
    fprintf(stderr, "[atem_rtm_real] RTM client destroyed\n");
}

int atem_rtm_connect(AtemRtmClient* client) {
    // In RTM 2.x, connection is established during login.
    // This is a no-op but kept for API compatibility.
    if (!client) return -1;
    return 0;
}

int atem_rtm_disconnect(AtemRtmClient* client) {
    if (!client || !client->rtm_client) return -1;

    uint64_t request_id = 0;
    client->rtm_client->logout(request_id);
    fprintf(stderr, "[atem_rtm_real] logout requested (requestId=%llu)\n",
            (unsigned long long)request_id);
    return 0;
}

int atem_rtm_login(
    AtemRtmClient* client,
    const char* token,
    const char* user_id) {
    if (!client || !client->rtm_client) return -1;
    (void)user_id;  // userId was already set at creation time in RTM 2.x

    const char* tok = (token && token[0] != '\0') ? token : client->token.c_str();

    uint64_t request_id = 0;
    client->rtm_client->login(tok, request_id);
    fprintf(stderr, "[atem_rtm_real] login requested (requestId=%llu)\n",
            (unsigned long long)request_id);
    return 0;
}

int atem_rtm_join_channel(
    AtemRtmClient* client,
    const char* channel_id) {
    if (!client || !client->rtm_client || !channel_id) return -1;

    agora::rtm::SubscribeOptions opts;
    opts.withMessage = true;
    opts.withPresence = true;
    opts.withMetadata = false;
    opts.withLock = false;

    uint64_t request_id = 0;
    client->rtm_client->subscribe(channel_id, opts, request_id);
    fprintf(stderr, "[atem_rtm_real] subscribe (join) channel=%s requestId=%llu\n",
            channel_id, (unsigned long long)request_id);
    return 0;
}

int atem_rtm_publish_channel(
    AtemRtmClient* client,
    const char* payload) {
    if (!client || !client->rtm_client || !payload) return -1;

    agora::rtm::PublishOptions opts;
    opts.channelType = agora::rtm::RTM_CHANNEL_TYPE_MESSAGE;
    opts.messageType = agora::rtm::RTM_MESSAGE_TYPE_STRING;

    const char* channel = client->channel.c_str();
    size_t length = strlen(payload);

    uint64_t request_id = 0;
    client->rtm_client->publish(channel, payload, length, opts, request_id);
    fprintf(stderr,
            "[atem_rtm_real] publish channel=%s len=%zu requestId=%llu\n",
            channel, length, (unsigned long long)request_id);
    return 0;
}

int atem_rtm_send_peer(
    AtemRtmClient* client,
    const char* target_client_id,
    const char* payload) {
    if (!client || !client->rtm_client || !target_client_id || !payload) return -1;

    // In RTM 2.x, peer messaging is done by publishing to the user channel type.
    agora::rtm::PublishOptions opts;
    opts.channelType = agora::rtm::RTM_CHANNEL_TYPE_USER;
    opts.messageType = agora::rtm::RTM_MESSAGE_TYPE_STRING;

    size_t length = strlen(payload);

    uint64_t request_id = 0;
    client->rtm_client->publish(target_client_id, payload, length, opts, request_id);
    fprintf(stderr,
            "[atem_rtm_real] send_peer target=%s len=%zu requestId=%llu\n",
            target_client_id, length, (unsigned long long)request_id);
    return 0;
}

int atem_rtm_set_token(
    AtemRtmClient* client,
    const char* token) {
    if (!client || !client->rtm_client || !token) return -1;

    uint64_t request_id = 0;
    client->rtm_client->renewToken(token, request_id);
    fprintf(stderr, "[atem_rtm_real] renewToken requestId=%llu\n",
            (unsigned long long)request_id);
    return 0;
}

int atem_rtm_subscribe_topic(
    AtemRtmClient* client,
    const char* channel,
    const char* topic) {
    if (!client || !client->rtm_client || !channel || !topic) return -1;

    // In RTM 2.x message channels, topics are not a first-class concept.
    // Topic subscription is relevant for stream channels. For message channels,
    // we subscribe to the channel itself which receives all messages.
    // We perform a regular channel subscribe here as a reasonable fallback.
    agora::rtm::SubscribeOptions opts;
    opts.withMessage = true;
    opts.withPresence = false;

    uint64_t request_id = 0;
    client->rtm_client->subscribe(channel, opts, request_id);
    fprintf(stderr,
            "[atem_rtm_real] subscribe_topic channel=%s topic=%s requestId=%llu\n",
            channel, topic, (unsigned long long)request_id);
    return 0;
}

} // extern "C"
