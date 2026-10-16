use anyhow::{Result, anyhow};
use libc::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{
    UnboundedReceiver, UnboundedSender, error::TryRecvError, unbounded_channel,
};

#[repr(C)]
struct AtemRtmClient {
    _private: [u8; 0],
}

#[repr(C)]
struct AtemRtmConfig {
    app_id: *const c_char,
    token: *const c_char,
    channel: *const c_char,
    client_id: *const c_char,
}

type AtemRtmMessageCallback = unsafe extern "C" fn(
    from_client_id: *const c_char,
    payload: *const c_char,
    user_data: *mut c_void,
);

#[allow(improper_ctypes)]
unsafe extern "C" {
    fn atem_rtm_create(
        config: *const AtemRtmConfig,
        callback: AtemRtmMessageCallback,
        user_data: *mut c_void,
    ) -> *mut AtemRtmClient;
    fn atem_rtm_destroy(client: *mut AtemRtmClient);
    fn atem_rtm_connect(client: *mut AtemRtmClient) -> i32;
    fn atem_rtm_disconnect(client: *mut AtemRtmClient) -> i32;
    fn atem_rtm_login(
        client: *mut AtemRtmClient,
        token: *const c_char,
        user_id: *const c_char,
    ) -> i32;
    fn atem_rtm_join_channel(client: *mut AtemRtmClient, channel_id: *const c_char) -> i32;
    fn atem_rtm_publish_channel(client: *mut AtemRtmClient, payload: *const c_char) -> i32;
    fn atem_rtm_send_peer(
        client: *mut AtemRtmClient,
        target_client_id: *const c_char,
        payload: *const c_char,
    ) -> i32;
    fn atem_rtm_set_token(client: *mut AtemRtmClient, token: *const c_char) -> i32;
    fn atem_rtm_subscribe_topic(
        client: *mut AtemRtmClient,
        channel: *const c_char,
        topic: *const c_char,
    ) -> i32;
}

pub struct RtmEvent {
    pub from: String,
    pub payload: String,
}

struct CallbackState {
    sender: UnboundedSender<RtmEvent>,
}

struct OwnedCString(*mut c_char);

impl OwnedCString {
    fn new(value: CString) -> Self {
        Self(value.into_raw())
    }

    fn as_ptr(&self) -> *const c_char {
        self.0
    }
}

impl Drop for OwnedCString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CString::from_raw(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

unsafe extern "C" fn on_message(
    from_client_id: *const c_char,
    payload: *const c_char,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }

    let state = unsafe { &*(user_data as *mut CallbackState) };
    let from = if from_client_id.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(from_client_id) }
            .to_string_lossy()
            .into_owned()
    };
    let payload = if payload.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(payload) }
            .to_string_lossy()
            .into_owned()
    };

    let _ = state.sender.send(RtmEvent { from, payload });
}

pub struct RtmClient {
    inner: Arc<Mutex<RtmInner>>,
    receiver: Mutex<UnboundedReceiver<RtmEvent>>,
    _state: *mut CallbackState,
    owned_strings: Vec<OwnedCString>,
}

struct RtmInner {
    handle: *mut AtemRtmClient,
}

impl Drop for RtmInner {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                atem_rtm_disconnect(self.handle);
                atem_rtm_destroy(self.handle);
            }
        }
    }
}

impl Drop for RtmClient {
    fn drop(&mut self) {
        unsafe {
            if !self._state.is_null() {
                drop(Box::from_raw(self._state));
                self._state = ptr::null_mut();
            }
        }
        // OwnedCString drops automatically
    }
}

pub struct RtmConfig {
    pub app_id: String,
    pub token: String,
    pub channel: String,
    pub client_id: String,
}

impl RtmClient {
    pub fn new(config: RtmConfig) -> Result<Self> {
        let (tx, rx) = unbounded_channel();
        let state = Box::new(CallbackState { sender: tx });
        let state_ptr = Box::into_raw(state);

        let mut owned_strings = Vec::new();
        let app_id = OwnedCString::new(CString::new(config.app_id)?);
        let token = OwnedCString::new(CString::new(config.token)?);
        let channel = OwnedCString::new(CString::new(config.channel)?);
        let client_id = OwnedCString::new(CString::new(config.client_id.clone())?);

        let cfg = AtemRtmConfig {
            app_id: app_id.as_ptr(),
            token: token.as_ptr(),
            channel: channel.as_ptr(),
            client_id: client_id.as_ptr(),
        };

        owned_strings.push(app_id);
        owned_strings.push(token);
        owned_strings.push(channel);
        owned_strings.push(client_id);

        let handle = unsafe { atem_rtm_create(&cfg, on_message, state_ptr as *mut _) };

        if handle.is_null() {
            unsafe {
                drop(Box::from_raw(state_ptr));
            }
            return Err(anyhow!("failed to create RTM client handle"));
        }

        let rc = unsafe { atem_rtm_connect(handle) };
        if rc != 0 {
            unsafe {
                atem_rtm_destroy(handle);
                drop(Box::from_raw(state_ptr));
            }
            return Err(anyhow!("failed to connect RTM client (code {rc})"));
        }

        let inner = RtmInner { handle };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            receiver: Mutex::new(rx),
            _state: state_ptr,
            owned_strings,
        })
    }

    pub async fn publish_channel(&self, payload: &str) -> Result<()> {
        let payload_c = CString::new(payload)?;
        let guard = self.inner.lock().await;
        let rc = unsafe { atem_rtm_publish_channel(guard.handle, payload_c.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!("failed to publish channel message (code {rc})"));
        }
        Ok(())
    }

    pub async fn login_and_join(&self, token: &str, account: &str, channel: &str) -> Result<()> {
        let token_c = CString::new(token)?;
        let account_c = CString::new(account)?;
        let channel_c = CString::new(channel)?;

        let handle = {
            let guard = self.inner.lock().await;
            guard.handle
        };

        let rc = unsafe { atem_rtm_login(handle, token_c.as_ptr(), account_c.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!("failed to login to signaling (code {rc})"));
        }

        let rc_join = unsafe { atem_rtm_join_channel(handle, channel_c.as_ptr()) };
        if rc_join != 0 {
            return Err(anyhow!(
                "failed to join signaling channel {} (code {rc_join})",
                channel
            ));
        }
        Ok(())
    }

    pub async fn send_peer(&self, target: &str, payload: &str) -> Result<()> {
        let target_c = CString::new(target)?;
        let payload_c = CString::new(payload)?;
        let guard = self.inner.lock().await;
        let rc = unsafe { atem_rtm_send_peer(guard.handle, target_c.as_ptr(), payload_c.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!("failed to send peer message (code {rc})"));
        }
        Ok(())
    }

    pub async fn next_event(&self) -> Option<RtmEvent> {
        let mut rx = self.receiver.lock().await;
        rx.recv().await
    }

    pub async fn drain_events(&self) -> Vec<RtmEvent> {
        let mut rx = self.receiver.lock().await;
        let mut events = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        events
    }

    pub async fn set_token(&self, token: &str) -> Result<()> {
        let token_c = CString::new(token)?;
        let guard = self.inner.lock().await;
        let rc = unsafe { atem_rtm_set_token(guard.handle, token_c.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!("failed to set token (code {rc})"));
        }
        Ok(())
    }

    pub async fn subscribe_topic(&self, channel: &str, topic: &str) -> Result<()> {
        let channel_c = CString::new(channel)?;
        let topic_c = CString::new(topic)?;
        let guard = self.inner.lock().await;
        let rc =
            unsafe { atem_rtm_subscribe_topic(guard.handle, channel_c.as_ptr(), topic_c.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!(
                "failed to subscribe topic {} on channel {} (code {rc})",
                topic,
                channel
            ));
        }
        Ok(())
    }

    pub async fn disconnect(&self) {
        let guard = self.inner.lock().await;
        unsafe {
            atem_rtm_disconnect(guard.handle);
        }
    }
}
