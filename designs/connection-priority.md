# Astation Connection Priority

Status: implemented.

## Order

1. Connect to `astation_ws`, defaulting to `ws://127.0.0.1:8080/ws`.
2. Complete device authentication v2 on that direct socket.
3. If direct connection fails and an Astation identity was learned previously,
   connect to that identity room at `astation_relay_url`.
4. Send `hello`, receive Astation's challenge through the relay, and complete
   the same v2 session proof or pairing flow.
5. If both paths fail, continue without Astation and retry later.

There is no separate session-ID URL attempt. `connect_with_session` is a
compatibility alias; authentication always happens after the WebSocket opens.

## Configuration

```toml
# Same Mac, also the default
astation_ws = "ws://127.0.0.1:8080/ws"

# Or direct LAN/VPN
# astation_ws = "ws://192.168.1.20:8080/ws"
# astation_ws = "ws://100.64.0.20:8080/ws"

# Remote fallback
astation_relay_url = "https://station.agora.build"
astation_relay_code = "astation-..."
```

Environment overrides are `ASTATION_WS`, `ASTATION_RELAY_URL`, and
`ASTATION_RELAY_CODE`. Successful authentication persists the relay code
automatically; the explicit value is an override for provisioning or recovery.

## Network behavior

| Scenario | Direct | Relay | Result |
|----------|--------|-------|--------|
| Same Mac, radios disabled | Loopback succeeds | Not used | Fully offline |
| Separate machine, same LAN, internet down | LAN IP succeeds | Not used | Fully offline after local routing works |
| Separate networks | Direct normally fails | WSS succeeds | Internet and relay required |
| Direct and relay both reachable | Direct wins | Standby fallback | Lowest-latency path |

Direct LAN clients still require first-use approval and later HMAC proofs. LAN
reachability never grants the loopback policy. See `session-auth.md` for the
protocol and the current plaintext-LAN limitation.

## Operational checks

- Disable Wi-Fi on the Astation Mac and verify the default loopback connection.
- Configure a real LAN address from a second host and verify operation with the
  internet uplink unavailable.
- Stop the direct listener and verify identity-relay fallback.
- Restore direct service and verify the same Astation session is reused.
- Confirm an invalid saved proof falls back to pairing without reconnecting.
