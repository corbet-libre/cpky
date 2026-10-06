//! Bounded owner-only same-origin channel. Its wire contains public data and
//! HPKE ciphertext; the private callback plaintext never enters this module.
use super::seal::{MAX_SEALED, Offer};
use crate::Error;
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::Uint8Array;
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{BroadcastChannel, Event, MessageEvent, Window};
use zeroize::Zeroizing;

const MAX_PACKET: usize = MAX_SEALED * 4 + 4096;
pub(super) const MAX_MILLIS: u32 = 120_000;
type CloseAction = Rc<RefCell<Option<Box<dyn FnMut()>>>>;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Packet {
    Hello {
        peer: [u8; 32],
    },
    Offer {
        peer: [u8; 32],
        offer: Offer,
    },
    Result {
        peer: [u8; 32],
        nonce: [u8; 32],
        sealed: Vec<u8>,
    },
    Ack {
        peer: [u8; 32],
    },
    Cancel {
        peer: [u8; 32],
    },
}

pub(super) struct Channel {
    channel: BroadcastChannel,
    receiver: mpsc::Receiver<Packet>,
    closed: Rc<Cell<bool>>,
    close: Rc<dyn Fn()>,
    on_close: CloseAction,
    window: Window,
    deadline: f64,
    _timer: gloo_timers::callback::Timeout,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(Event)>,
    pagehide: Closure<dyn FnMut(Event)>,
    pub cancel: Option<[u8; 32]>,
}

impl Channel {
    pub fn new(name: &str, origin: &str, millis: u32) -> Result<Self, Error> {
        if millis == 0 || millis > MAX_MILLIS {
            return Err(Error::InvalidOptions);
        }
        let window = web_sys::window().ok_or(Error::Unavailable)?;
        let deadline = now(&window)? + f64::from(millis);
        let channel = BroadcastChannel::new(name).map_err(|_| Error::Unavailable)?;
        let (sender, receiver) = mpsc::channel(4);
        let sender = Rc::new(RefCell::new(sender));
        let closed = Rc::new(Cell::new(false));
        let on_close: CloseAction = Rc::new(RefCell::new(None));
        let stop = {
            let sender = sender.clone();
            let closed = closed.clone();
            let on_close = on_close.clone();
            Rc::new(move || {
                closed.set(true);
                sender.borrow_mut().close_channel();
                if let Some(mut action) = on_close.borrow_mut().take() {
                    action();
                }
            })
        };
        let message = {
            let stop = stop.clone();
            let origin = origin.to_owned();
            let closed = closed.clone();
            Closure::new(move |event: MessageEvent| {
                if closed.get() {
                    return;
                }
                if !event.is_trusted() || event.origin() != origin || event.ports().length() != 0 {
                    stop();
                    return;
                }
                // Reject length/type before copying or parsing anything. Never
                // accept strings, transferred ports, secret objects or aliases.
                let data = event.data();
                let Some(view) = data.dyn_ref::<Uint8Array>() else {
                    stop();
                    return;
                };
                if view.length() as usize > MAX_PACKET {
                    stop();
                    return;
                }
                let bytes = Zeroizing::new(view.to_vec());
                view.fill(0, 0, view.length());
                let packet = serde_json::from_slice(&bytes);
                match packet {
                    Ok(packet) => {
                        let refused = sender.borrow_mut().try_send(packet).is_err();
                        if refused {
                            stop();
                        }
                    }
                    Err(_) => stop(),
                }
            })
        };
        let error = {
            let stop = stop.clone();
            Closure::new(move |_: Event| stop())
        };
        let pagehide = {
            let stop = stop.clone();
            Closure::new(move |_: Event| stop())
        };
        window
            .add_event_listener_with_callback("pagehide", pagehide.as_ref().unchecked_ref())
            .map_err(|_| {
                channel.close();
                Error::Unavailable
            })?;
        channel.set_onmessage(Some(message.as_ref().unchecked_ref()));
        channel.set_onmessageerror(Some(error.as_ref().unchecked_ref()));
        let timer_stop = stop.clone();
        let timer = gloo_timers::callback::Timeout::new(millis, move || timer_stop());
        Ok(Self {
            channel,
            receiver,
            closed,
            close: stop,
            on_close,
            window,
            deadline,
            _timer: timer,
            _message: message,
            _error: error,
            pagehide,
            cancel: None,
        })
    }

    pub fn check(&self) -> Result<(), Error> {
        if self.closed.get() || now(&self.window)? >= self.deadline {
            (self.close)();
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn expire_with(&self, mut action: impl FnMut() + 'static) {
        if self.closed.get() {
            action();
        } else {
            *self.on_close.borrow_mut() = Some(Box::new(action));
        }
    }

    pub fn post(&self, packet: &Packet) -> Result<(), Error> {
        self.check()?;
        post(&self.channel, packet)
    }

    pub async fn next(&mut self) -> Result<Packet, Error> {
        self.check()?;
        let packet = self.receiver.next().await.ok_or(Error::Cancelled)?;
        self.check()?;
        Ok(packet)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if let Some(peer) = self.cancel {
            let _ = post(&self.channel, &Packet::Cancel { peer });
        }
        (self.close)();
        self.receiver.close();
        self.channel.set_onmessage(None);
        self.channel.set_onmessageerror(None);
        self.channel.close();
        let _ = self.window.remove_event_listener_with_callback(
            "pagehide",
            self.pagehide.as_ref().unchecked_ref(),
        );
    }
}

fn post(channel: &BroadcastChannel, packet: &Packet) -> Result<(), Error> {
    let bytes = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| Error::InvalidResponse)?);
    if bytes.len() > MAX_PACKET {
        return Err(Error::InvalidResponse);
    }
    let view = Uint8Array::from(bytes.as_slice());
    // postMessage performs structured serialization synchronously. Wipe our JS
    // copy after that step; receivers wipe their separate copy before parsing.
    let result = channel
        .post_message(view.as_ref())
        .map_err(|_| Error::Unavailable);
    view.fill(0, 0, view.length());
    result
}

fn now(window: &Window) -> Result<f64, Error> {
    let time = window.performance().ok_or(Error::Unavailable)?.now();
    if time.is_finite() {
        Ok(time)
    } else {
        Err(Error::Unavailable)
    }
}
