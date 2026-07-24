//! Idle timeout and keep-alive scheduling (draft-ietf-quic-qmux-02 §8)
//!
//! The effective timeout is negotiated exactly as in QUIC (the minimum of both endpoints'
//! nonzero `max_idle_timeout`, via the shared [`negotiate_max_idle_timeout`]). What
//! differs on a reliable transport is what arms the timer: receiving a record always
//! re-arms the deadline, while sending a record extends it at most once per receive, so
//! that our own keep-alive pings cannot keep a connection with an unresponsive peer alive
//! indefinitely. Acknowledgments are invisible at this layer and never reset the timer.
//!
//! Keep-alive QX_PING requests follow quinn's model: sent at `keep_alive_interval` when
//! configured, disabled otherwise.

use super::super::negotiate_max_idle_timeout;
use crate::{Duration, Instant, VarInt};

#[derive(Debug)]
pub(super) struct IdleTimer {
    /// Our `max_idle_timeout` transport parameter, in milliseconds
    local: Option<VarInt>,
    keepalive: Option<Duration>,
    effective: Option<Duration>,
    deadline: Option<Instant>,
    keepalive_at: Option<Instant>,
    sent_since_recv: bool,
}

impl IdleTimer {
    pub(super) fn new(local: Option<VarInt>, keepalive: Option<Duration>, now: Instant) -> Self {
        let mut this = Self {
            local,
            keepalive,
            effective: negotiate_max_idle_timeout(local, None),
            deadline: None,
            keepalive_at: None,
            sent_since_recv: false,
        };
        this.rearm(now);
        this
    }

    /// Apply the peer's `max_idle_timeout` parameter (0 = no limit on their side)
    pub(super) fn set_peer_timeout(&mut self, peer: VarInt, now: Instant) {
        self.effective = negotiate_max_idle_timeout(self.local, Some(peer));
        self.rearm(now);
    }

    fn rearm(&mut self, now: Instant) {
        self.deadline = self.effective.map(|timeout| now + timeout);
        self.keepalive_at = self.keepalive.map(|interval| now + interval);
        self.sent_since_recv = false;
    }

    pub(super) fn on_record_received(&mut self, now: Instant) {
        self.rearm(now);
    }

    pub(super) fn on_record_sent(&mut self, now: Instant) {
        let Some(timeout) = self.effective else {
            return;
        };
        if !self.sent_since_recv {
            self.sent_since_recv = true;
            self.deadline = self.deadline.max(Some(now + timeout));
        }
    }

    /// The next instant at which `handle_timeout` should run
    pub(super) fn next_timeout(&self) -> Option<Instant> {
        match (self.deadline, self.keepalive_at) {
            (Some(deadline), Some(keepalive)) => Some(deadline.min(keepalive)),
            (deadline, keepalive) => deadline.or(keepalive),
        }
    }

    /// Whether the connection has been idle past the effective timeout
    pub(super) fn is_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Whether a keep-alive ping is due; re-arms the keep-alive interval when it is
    pub(super) fn poll_keepalive(&mut self, now: Instant) -> bool {
        let Some(at) = self.keepalive_at else {
            return false;
        };
        if now < at {
            return false;
        }
        self.keepalive_at = Some(now + self.keepalive.expect("keepalive_at without interval"));
        true
    }
}
