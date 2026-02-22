# Quick Test Checklist - v0.4.31

Fast validation checklist for testing releases.

---

## 🚀 Pre-Test Setup (1 min)

```bash
# On your Mac:
cd ~/Dev/Agora.Build/Atem
git pull
cargo build --release

cd ~/Dev/Agora.Build/Astation
git pull
swift build --release
# Quit old Astation, run: .build/release/Astation

# Clean slate:
rm ~/.config/atem/session.json ~/.config/atem/config.toml
```

---

## ✅ Critical Path Test (5 min)

### Test 1: First Connection + Save Credentials
```bash
./target/release/atem
```
**Check:**
- [ ] Pairing dialog appears on Mac
- [ ] Click "Allow" → "Connected to Astation" ✓
- [ ] "Press 'y' to save, 'n' for session only" prompt appears
- [ ] Press 'y' → "✅ Credentials saved to config" ✓
- [ ] Top banner shows: "🔑 Credentials: from config file" ✓
- [ ] Navigate to "List Agora Projects" → projects load ✓

### Test 2: Session Reuse (No Re-Pairing)
```bash
# Quit Atem (press 'q')
./target/release/atem
```
**Check:**
- [ ] NO pairing dialog (connects immediately) ✓
- [ ] NO credential prompt (already saved) ✓
- [ ] Projects load immediately ✓

### Test 3: Multiple Instances
```bash
# Terminal 1
./target/release/atem &

# Terminal 2
./target/release/atem &
```
**Check in Astation UI:**
- [ ] Shows "2 online" clients ✓
- [ ] Both have same hostname, different client IDs ✓
- [ ] Quit one → immediately shows "1 online" (no OFFLINE) ✓

### Test 4: Temporary Credentials (Don't Save)
```bash
rm ~/.config/atem/config.toml  # Remove saved credentials
./target/release/atem
```
**Check:**
- [ ] Reconnects (uses session, no re-pairing) ✓
- [ ] CredentialSync received → prompt appears ✓
- [ ] Press 'n' → "Using credentials for this session only" ✓
- [ ] Projects still load (credentials work!) ✓
- [ ] Quit + relaunch → prompt appears again ✓

---

## 🎯 Pass Criteria

**ALL 4 tests PASS** = ✅ Ready to ship!

**Any test FAILS** = ❌ Fix before release

---

## 🐛 Common Issues & Fixes

### Issue: "No credentials" warning persists
**Fix:** Make sure Astation has credentials in Settings

### Issue: Re-pairing on every launch
**Fix:** Check session.json exists and is valid

### Issue: Projects fail to load
**Fix:** Verify Astation credentials are correct

### Issue: Multiple instances show as duplicates
**Fix:** This is expected! Each instance = separate client

---

## 📋 Files to Verify

After successful test:
```bash
# Session saved
ls -lh ~/.config/atem/session.json

# Credentials saved (after pressing 'y')
cat ~/.config/atem/config.toml | grep customer_id
```

Expected output:
```toml
customer_id = "ab12cd34..."
customer_secret = "********"
```

---

## ⏱️ Total Test Time

- Fresh install test: ~2 min
- Session reuse: ~30 sec
- Multiple instances: ~1 min
- Temp credentials: ~1 min

**Total: ~5 minutes** for complete validation ✓
