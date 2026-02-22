# Atem & Astation Test Cases

Comprehensive test scenarios for v0.4.31 release.

---

## 🧪 Test Environment Setup

**Prerequisites:**
- Astation running on Mac (latest build)
- Atem built on Mac: `cargo build --release`
- Astation has Agora credentials configured in Settings
- Clean slate: `rm ~/.config/atem/session.json ~/.config/atem/config.toml`

**Test Machine:** Mac (same machine as Astation for local testing)

---

## Test Suite 1: First-Time Pairing & Authentication

### TC-001: Fresh Install - First Launch with Pairing

**Objective:** Verify first-time pairing flow works correctly

**Preconditions:**
- No session file: `rm ~/.config/atem/session.json`
- No config file: `rm ~/.config/atem/config.toml`
- Astation running with credentials saved

**Steps:**
1. Launch Atem TUI: `./target/release/atem`
2. Observe connection status
3. Check Astation for pairing dialog
4. Click "Allow" on pairing dialog
5. Observe Atem TUI status message
6. Wait for CredentialSync message
7. Observe prompt: "Press 'y' to save, 'n' for session only"
8. Press 'y' to save credentials
9. Navigate to "List Agora Projects" in menu
10. Press Enter to select

**Expected Results:**
- ✅ Atem shows "Connecting to Astation..."
- ✅ Pairing code displayed (e.g., "123456")
- ✅ Astation shows dialog: "Atem Pairing Request - Brents-Station-Pro.local - Code: 123456"
- ✅ After approval: Atem shows "Connected to Astation"
- ✅ Status bar turns green: "Connected to Astation | ..."
- ✅ Prompt appears: "🔑 Credentials received (...) | Press 'y' to save, 'n' to use for this session only"
- ✅ After pressing 'y': "✅ Credentials saved to config (...)"
- ✅ Top banner changes from "⚠️ No credentials" to "🔑 Credentials: from config file"
- ✅ Projects list loads successfully
- ✅ Session saved to `~/.config/atem/session.json`
- ✅ Credentials saved to `~/.config/atem/config.toml`

**Validation:**
```bash
# Check session file exists
ls -lh ~/.config/atem/session.json

# Check credentials saved
grep "customer_id" ~/.config/atem/config.toml

# Verify Astation shows 1 online client
# Check Astation Clients & Agents panel
```

---

### TC-002: Fresh Install - Save Credentials = NO

**Objective:** Verify credentials work in-memory without persisting to disk

**Preconditions:**
- No session file: `rm ~/.config/atem/session.json`
- No config file: `rm ~/.config/atem/config.toml`
- Astation running

**Steps:**
1. Launch Atem: `./target/release/atem`
2. Complete pairing (approve on Astation)
3. When prompted "Press 'y' to save, 'n' for session only"
4. Press 'n' (do NOT save)
5. Navigate to "List Agora Projects"
6. Press Enter
7. Quit Atem (press 'q')
8. Relaunch Atem: `./target/release/atem`

**Expected Results:**
- ✅ After pressing 'n': "🔑 Using credentials for this session only (...)"
- ✅ Top banner shows: "🔑 Credentials: synced from Astation | 🟢 Astation connected"
- ✅ Projects list loads successfully (credentials work!)
- ✅ Config file NOT created (or customer_id NOT in config)
- ✅ After quit + relaunch: reconnects with session (no re-pairing)
- ✅ CredentialSync received again
- ✅ Prompt shows again: "Press 'y' to save, 'n' for session only"

**Validation:**
```bash
# Session should exist (no re-pairing needed)
cat ~/.config/atem/session.json

# Credentials should NOT be in config
grep "customer_id" ~/.config/atem/config.toml  # Should be empty or not found
```

**Use Case:** Temporary access on shared machine, don't persist credentials

---

## Test Suite 2: Session Reuse & Multiple Instances

### TC-003: Session Reuse - No Re-Pairing

**Objective:** Verify saved session works without re-pairing

**Preconditions:**
- Session exists from TC-001
- Credentials saved in config
- Astation running

**Steps:**
1. Quit Atem if running
2. Launch Atem: `./target/release/atem`
3. Observe connection behavior

**Expected Results:**
- ✅ NO pairing dialog shown
- ✅ Connects immediately: "Connected to Astation"
- ✅ NO CredentialSync prompt (already saved)
- ✅ Top banner: "🔑 Credentials: from config file"
- ✅ Projects list works immediately

**Timing:** Connection should complete in < 2 seconds

---

### TC-004: Multiple Instances - Same Machine

**Objective:** Verify multiple Atem instances can run simultaneously

**Preconditions:**
- Session exists
- Credentials saved
- Astation running

**Steps:**
1. Launch Atem instance 1: `./target/release/atem` (Terminal 1)
2. Wait for connection
3. Launch Atem instance 2: `./target/release/atem` (Terminal 2)
4. Wait for connection
5. Launch Atem instance 3 (login): `./target/release/atem login` (Terminal 3)
6. Check Astation "Clients & Agents" panel
7. In instance 1: List projects
8. In instance 2: List projects (at same time)
9. Quit instance 2 (press 'q')
10. Check Astation panel again

**Expected Results:**
- ✅ All 3 instances connect successfully
- ✅ NO re-pairing for any instance (all use same session)
- ✅ Astation shows "3 online" clients
- ✅ Each client has unique client ID (different entry)
- ✅ All show same hostname: "Brents-Station-Pro.local"
- ✅ Projects load in both instance 1 and 2 simultaneously
- ✅ After quitting instance 2: Astation shows "2 online"
- ✅ Instance 2 REMOVED immediately (not shown as OFFLINE)

**Validation:**
```bash
# Check Astation UI - should show separate clients:
# - Brents-Station-Pro.local (connected 5s ago)
# - Brents-Station-Pro.local (connected 3s ago)
# - Brents-Station-Pro.local (connected 1s ago)
```

---

### TC-005: OFFLINE Client Cleanup

**Objective:** Verify disconnected clients are removed, not marked OFFLINE

**Preconditions:**
- 3 Atem instances running (from TC-004)
- Astation shows "3 online"

**Steps:**
1. Quit instance 1 (press 'q')
2. Immediately check Astation panel
3. Wait 2 seconds
4. Quit instance 2 (press 'q')
5. Check Astation panel
6. Quit instance 3
7. Check Astation panel

**Expected Results:**
- ✅ After quit #1: "2 online" (IMMEDIATELY, no delay)
- ✅ NO "OFFLINE" section shown
- ✅ After quit #2: "1 online"
- ✅ After quit #3: "0 online" + empty state message
- ✅ No ghost/stale entries remain

**This should FAIL on old Astation, PASS on new Astation**

---

## Test Suite 3: Credential Sync Edge Cases

### TC-006: Atem Login Command - Save Credentials

**Objective:** Verify `atem login` credential sync with save

**Preconditions:**
- Session exists (no re-pairing needed)
- Config does NOT have credentials: `rm ~/.config/atem/config.toml`
- Astation running with credentials

**Steps:**
1. Run: `./target/release/atem login`
2. Observe output
3. When prompted "Sync Agora credentials from Astation? [Y/n]"
4. Press Enter (default = Yes)
5. Wait for completion
6. Check config file

**Expected Results:**
```
Authenticating with Astation...
Connected to local Astation!
Waiting for pairing approval...
✓ Authenticated successfully!
Sync Agora credentials from Astation? [Y/n]
Syncing Agora credentials from Astation...
✓ Credentials saved (customer_id: ab12...)
```

**Validation:**
```bash
grep "customer_id" ~/.config/atem/config.toml  # Should exist
```

---

### TC-007: Atem Login Command - Don't Save

**Objective:** Verify `atem login` respects "no" choice

**Preconditions:**
- Session exists
- No credentials in config

**Steps:**
1. Run: `./target/release/atem login`
2. When prompted "Sync Agora credentials? [Y/n]"
3. Type 'n' and press Enter
4. Check config file
5. Run: `./target/release/atem login` again

**Expected Results:**
- ✅ After 'n': command completes without errors
- ✅ Config file NOT created or customer_id NOT added
- ✅ Second run: prompts again (not saved)

---

### TC-008: Astation WITHOUT Credentials

**Objective:** Verify behavior when Astation has no credentials configured

**Preconditions:**
- Open Astation Settings
- Click "Delete Credentials" (remove Agora credentials)
- No credentials in Atem config

**Steps:**
1. Launch Atem: `./target/release/atem`
2. Complete pairing if needed
3. Wait for connection
4. Try to list projects

**Expected Results:**
- ✅ Connects successfully to Astation
- ✅ NO CredentialSync message received (Astation has no credentials to send)
- ✅ NO prompt shown (no credentials to save)
- ✅ Top banner: "⚠️ No credentials - run `atem login` or set AGORA_CUSTOMER_ID"
- ✅ List projects shows error: "Failed to fetch Agora projects: No credentials found..."

**Recovery:**
1. Add credentials to Astation Settings
2. Quit and relaunch Atem
3. Should receive CredentialSync and prompt

---

## Test Suite 4: Network & Connection Scenarios

### TC-009: Connection Priority - Local First

**Objective:** Verify local connection is tried before relay

**Preconditions:**
- Session exists
- Config: `astation_ws = "ws://127.0.0.1:8080/ws"`
- Config: `astation_relay_url = "https://station.agora.build"`
- Astation running locally

**Steps:**
1. Launch Atem: `./target/release/atem`
2. Observe connection timing (should be fast)
3. Check Astation shows new client

**Expected Results:**
- ✅ Connects to local Astation (not relay)
- ✅ Connection time: < 1 second
- ✅ No relay traffic (check network tab if possible)

---

### TC-010: Relay Fallback (Local Unavailable)

**Objective:** Verify relay fallback works when local is unavailable

**Preconditions:**
- Session exists
- Config has both local and relay URLs
- Config: `astation_relay_code = "astation-abc-123"` (your Astation ID)
- **Quit Astation** (local not available)

**Steps:**
1. Launch Atem: `./target/release/atem`
2. Observe connection behavior
3. Wait for connection

**Expected Results:**
- ✅ Local connection attempt fails (expected)
- ✅ Falls back to relay automatically
- ✅ Connects via relay (slower, 2-5 seconds)
- ✅ Shows "Connected to Astation" (user doesn't see difference)

**Note:** This requires relay server running and accessible

---

## Test Suite 5: Session Expiration & Re-Pairing

### TC-011: Expired Session - Auto Re-Pair

**Objective:** Verify expired sessions trigger re-pairing

**Preconditions:**
- Session exists but is EXPIRED (manually edit session.json to old date)
- Or wait 7 days (not practical for testing)

**Manual Expiry:**
```bash
# Edit session file to expire it
nano ~/.config/atem/session.json
# Change "lastActivity" to 8 days ago
```

**Steps:**
1. Launch Atem: `./target/release/atem`
2. Observe behavior

**Expected Results:**
- ✅ Detects expired session
- ✅ Starts pairing flow (shows pairing code)
- ✅ After approval: new session created
- ✅ Connects successfully

---

## Test Suite 6: Integration & Real-World Usage

### TC-012: Complete Workflow - New User

**Objective:** Full end-to-end workflow for a new user

**Preconditions:**
- Fresh install (no session, no config)
- Astation running with credentials

**Scenario:** New developer setting up Atem for the first time

**Steps:**
1. Download and install Atem
2. Run `atem` for the first time
3. See pairing dialog on Mac, approve
4. See credential save prompt, press 'y'
5. Navigate to "List Agora Projects"
6. See list of projects
7. Quit Atem
8. Relaunch Atem next day
9. Try listing projects again

**Expected Results:**
- ✅ Day 1: Pairing works smoothly
- ✅ Day 1: Credentials saved
- ✅ Day 1: Projects load
- ✅ Day 2: No re-pairing (uses session)
- ✅ Day 2: No credential prompt (already saved)
- ✅ Day 2: Works immediately

**User Experience:** Seamless after initial setup

---

### TC-013: Shared Machine - Security Conscious User

**Objective:** User who doesn't want to save credentials on disk

**Preconditions:**
- Fresh install
- Shared/public machine

**Scenario:** Developer on a shared work machine

**Steps:**
1. Run `atem`
2. Complete pairing
3. When prompted for credential save, press 'n' (don't save)
4. Use Atem for work (list projects, generate tokens)
5. Finish work, quit Atem
6. Next day, colleague uses the machine
7. Colleague runs `atem`

**Expected Results:**
- ✅ Original user: credentials work during session
- ✅ Original user: credentials NOT saved to disk
- ✅ After quit: credentials cleared from memory
- ✅ Next user: sees credential prompt (no leftover credentials)
- ✅ Secure: no credential leakage

---

## Test Suite 7: Error Handling & Recovery

### TC-014: Network Interruption During Session

**Objective:** Verify behavior when network connection drops

**Preconditions:**
- Atem connected to Astation
- Session active

**Steps:**
1. Connect Atem to Astation
2. While connected, quit Astation app (simulates network drop)
3. Try to list projects in Atem
4. Restart Astation
5. Quit and relaunch Atem

**Expected Results:**
- ✅ After Astation quits: Atem shows connection lost (graceful)
- ✅ Project list fails with network error
- ✅ After restart + relaunch: reconnects successfully

---

### TC-015: Pairing Denial

**Objective:** Verify behavior when user denies pairing

**Preconditions:**
- No session
- Astation running

**Steps:**
1. Launch Atem: `./target/release/atem`
2. See pairing dialog on Astation
3. Click "Deny" (reject pairing)
4. Observe Atem behavior

**Expected Results:**
- ✅ Atem shows error: "Pairing denied by user"
- ✅ Falls back to local mode (no Astation features)
- ✅ Can still use Atem (offline mode)

---

## 📊 Test Summary Template

After running tests, fill this out:

```
Test Run: v0.4.31
Date: [DATE]
Tester: [NAME]
Environment: macOS [VERSION]

Results:
✅ TC-001: PASS
✅ TC-002: PASS
✅ TC-003: PASS
...

Issues Found:
- [Issue description]

Notes:
- [Any observations]
```

---

## 🎯 Acceptance Criteria

**All tests must PASS for release:**

Critical (Must Pass):
- ✅ TC-001: First-time pairing works
- ✅ TC-003: Session reuse works
- ✅ TC-004: Multiple instances supported
- ✅ TC-005: No OFFLINE ghost clients
- ✅ TC-006: Credential save works (y)
- ✅ TC-002: Credential temp works (n)

Important (Should Pass):
- ✅ TC-007: Login command respects choices
- ✅ TC-009: Local connection priority
- ✅ TC-012: Complete new user workflow

Nice to Have:
- ✅ TC-010: Relay fallback
- ✅ TC-011: Session expiration handling
- ✅ TC-014: Network interruption graceful

---

## 🔧 Test Automation (Future)

These test cases can be automated using:
- Rust integration tests
- Swift XCTest for Astation
- GitHub Actions CI/CD

Current: Manual testing required ✓
