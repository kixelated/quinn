//! Idle timeout and keep-alive scheduling (draft-ietf-quic-qmux-02 §8)
//!
//! Receiving a record always re-arms the idle deadline. Sending a record extends it at
//! most once per receive, so that our own keep-alive pings cannot keep a connection with
//! an unresponsive peer alive indefinitely. QX_PING requests are scheduled at a third of
//! the idle timeout.

use crate::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct IdleTimer {
    /// Our configured limit; the effective timeout is the minimum of both endpoints'
    local: Option<Duration>,
    effective: Option<Duration>,
    deadline: Option<Instant>,
    keepalive_at: Option<Instant>,
    sent_since_recv: bool,
}

impl IdleTimer {
    pub(crate) fn new(local: Option<Duration>, now: Instant) -> Self {
        let mut this = Self {
            local,
            effective: local,
            deadline: None,
            keepalive_at: None,
            sent_since_recv: false,
        };
        this.rearm(now);
        this
    }

    /// Apply the peer's `max_idle_timeout` parameter (0 = no limit on their side)
    pub(crate) fn set_peer_timeout(&mut self, peer_ms: u64, now: Instant) {
        let peer = match peer_ms {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        };
        self.effective = match (self.local, peer) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.rearm(now);
    }

    fn rearm(&mut self, now: Instant) {
        let Some(timeout) = self.effective else {
            self.deadline = None;
            self.keepalive_at = None;
            return;
        };
        self.deadline = Some(now + timeout);
        self.keepalive_at = Some(now + timeout / 3);
        self.sent_since_recv = false;
    }

    pub(crate) fn on_record_received(&mut self, now: Instant) {
        self.rearm(now);
    }

    pub(crate) fn on_record_sent(&mut self, now: Instant) {
        let Some(timeout) = self.effective else {
            return;
        };
        if !self.sent_since_recv {
            self.sent_since_recv = true;
            self.deadline = self.deadline.max(Some(now + timeout));
        }
    }

    /// The next instant at which `handle_timeout` should run
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        match (self.deadline, self.keepalive_at) {
            (Some(d), Some(k)) => Some(d.min(k)),
            (d, k) => d.or(k),
        }
    }

    /// Whether the connection has been idle past the effective timeout
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// Whether a keep-alive ping is due; re-arms the keep-alive interval when it is
    pub(crate) fn poll_keepalive(&mut self, now: Instant) -> bool {
        let Some(at) = self.keepalive_at else {
            return false;
        };
        if now < at {
            return false;
        }
        let timeout = self.effective.expect("keepalive without timeout");
        self.keepalive_at = Some(now + timeout / 3);
        true
    }
}
