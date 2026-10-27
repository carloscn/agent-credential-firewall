//! Hash-chained JSON-lines audit log (ADR 0005).
//!
//! Every event carries `chain: {log, seq, prev}`. An event's hash is the
//! SHA-256 of its exact line bytes, so the chain covers what is on disk.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AuditError, AuditEvent, AuditSink};

const GENESIS_DOMAIN: &[u8] = b"acf.audit-chain/v1";

/// An event's position in its log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLink {
    /// Log identifier, `log-` plus 32 hex digits.
    pub log: String,
    /// Position, from 0 without gaps.
    pub seq: u64,
    /// Hash of the previous event, or [`genesis`] for the first.
    pub prev: String,
}

/// The newest event of a log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// Log identifier.
    pub log: String,
    /// Its sequence number.
    pub seq: u64,
    /// Its hash.
    pub hash: String,
}

fn hex_sha256(parts: &[&[u8]]) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for part in parts {
        context.update(part);
    }
    let mut text = String::from("sha256:");
    for byte in context.finish().as_ref() {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The `prev` of a log's first event.
#[must_use]
pub fn genesis(log: &str) -> String {
    hex_sha256(&[GENESIS_DOMAIN, &[0], log.as_bytes()])
}

/// The hash of one event line, without its trailing newline.
#[must_use]
pub fn line_hash(line: &[u8]) -> String {
    hex_sha256(&[line])
}

fn new_log_id() -> Result<String, AuditError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AuditError::Random)?;
    let mut text = String::from("log-");
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}

/// Bounds how long the log may run ahead of its newest accepted checkpoint
/// (ADR 0005 failure policy).
#[derive(Debug)]
pub struct AnchorState {
    max_lag: Duration,
    state: Mutex<(Instant, Option<u64>)>,
}

impl AnchorState {
    /// Starts the clock now, with nothing anchored yet.
    #[must_use]
    pub fn new(max_lag: Duration) -> Self {
        Self {
            max_lag,
            state: Mutex::new((Instant::now(), None)),
        }
    }

    /// Records that a checkpoint for `seq` was accepted.
    pub fn anchored(&self, seq: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = (Instant::now(), Some(seq));
    }

    /// The newest anchored sequence number.
    #[must_use]
    pub fn anchored_seq(&self) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
    }

    /// Whether a new event may be written after `head`. It may not when
    /// events beyond the newest checkpoint have waited longer than the
    /// maximum lag.
    fn admits(&self, head: Option<&ChainHead>) -> bool {
        let (since, anchored) = *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let unanchored = match (head, anchored) {
            (None, _) => false,
            (Some(head), Some(seq)) => head.seq > seq,
            (Some(_), None) => true,
        };
        !(unanchored && since.elapsed() > self.max_lag)
    }
}

struct State {
    writer: Box<dyn Write + Send>,
    log: String,
    next_seq: u64,
    prev: String,
    head: Option<ChainHead>,
    /// A write failed part-way; nothing more may be appended.
    broken: bool,
}

/// Writes chained events, one JSON object per line, flushing each.
pub struct ChainedJsonSink {
    state: Mutex<State>,
    anchor: Option<Arc<AnchorState>>,
}

/// The last complete line of `bytes`, which must end with a newline.
fn last_line(bytes: &[u8]) -> Result<&[u8], AuditError> {
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| AuditError::Continue("the file ends with a partial record".to_owned()))?;
    Ok(body
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(body, |i| &body[i + 1..]))
}

fn head_of(line: &[u8]) -> Result<ChainHead, AuditError> {
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| AuditError::Continue("the last record is not JSON".to_owned()))?;
    let chained: ChainLink = value
        .get("chain")
        .cloned()
        .and_then(|chain| serde_json::from_value(chain).ok())
        .ok_or_else(|| AuditError::Continue("the last record is not chained".to_owned()))?;
    Ok(ChainHead {
        log: chained.log,
        seq: chained.seq,
        hash: line_hash(line),
    })
}

/// Reads enough of the end of `file` to contain its last line.
fn tail(file: &mut File) -> Result<Vec<u8>, AuditError> {
    let io = |e: std::io::Error| AuditError::Continue(e.to_string());
    let length = file.seek(SeekFrom::End(0)).map_err(io)?;
    let mut window: u64 = 64 * 1024;
    loop {
        let start = length.saturating_sub(window);
        file.seek(SeekFrom::Start(start)).map_err(io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io)?;
        let interior_newline = bytes
            .strip_suffix(b"\n")
            .is_some_and(|body| body.contains(&b'\n'));
        if start == 0 || interior_newline {
            return Ok(bytes);
        }
        window = window.saturating_mul(4);
    }
}

impl ChainedJsonSink {
    /// Starts a new log on `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Random`] if no log identifier can be drawn.
    pub fn new(writer: Box<dyn Write + Send>) -> Result<Self, AuditError> {
        let log = new_log_id()?;
        Ok(Self::from_state(State {
            writer,
            prev: genesis(&log),
            log,
            next_seq: 0,
            head: None,
            broken: false,
        }))
    }

    /// Continues the log whose existing bytes end with `existing`, or starts
    /// a new one if `existing` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Continue`] if `existing` ends with a partial
    /// record or its last record is not a chained event.
    pub fn continuing(writer: Box<dyn Write + Send>, existing: &[u8]) -> Result<Self, AuditError> {
        if existing.is_empty() {
            return Self::new(writer);
        }
        let head = head_of(last_line(existing)?)?;
        Ok(Self::from_state(State {
            writer,
            log: head.log.clone(),
            next_seq: head.seq + 1,
            prev: head.hash.clone(),
            head: Some(head),
            broken: false,
        }))
    }

    /// Opens `path` for appending and continues its log, or starts a new one
    /// if the file is new or empty.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Continue`] if the file cannot be opened or
    /// continued.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::Continue(format!("{}: {e}", path.display())))?;
        let existing = tail(&mut file)?;
        Self::continuing(Box::new(file), &existing)
    }

    fn from_state(state: State) -> Self {
        Self {
            state: Mutex::new(state),
            anchor: None,
        }
    }

    /// Refuses new events when `anchor` says the log has run too far ahead
    /// of its newest checkpoint.
    #[must_use]
    pub fn with_anchor(mut self, anchor: Arc<AnchorState>) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// The newest event written, if any.
    #[must_use]
    pub fn head(&self) -> Option<ChainHead> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .head
            .clone()
    }

    /// This log's identifier.
    #[must_use]
    pub fn log(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .log
            .clone()
    }
}

#[async_trait]
impl AuditSink for ChainedJsonSink {
    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError::Unavailable)?;
        if state.broken {
            return Err(AuditError::Unavailable);
        }
        if let Some(anchor) = &self.anchor
            && !anchor.admits(state.head.as_ref())
        {
            return Err(AuditError::Unanchored);
        }
        let mut chained = event.clone();
        chained.chain = Some(ChainLink {
            log: state.log.clone(),
            seq: state.next_seq,
            prev: state.prev.clone(),
        });
        let mut line = serde_json::to_vec(&chained).map_err(|_| AuditError::Unavailable)?;
        let hash = line_hash(&line);
        line.push(b'\n');
        if state
            .writer
            .write_all(&line)
            .and_then(|()| state.writer.flush())
            .is_err()
        {
            // A partial line may be on disk; appending after it would hide
            // it. Startup refuses such a file until it is rotated.
            state.broken = true;
            return Err(AuditError::Unavailable);
        }
        state.head = Some(ChainHead {
            log: state.log.clone(),
            seq: state.next_seq,
            hash: hash.clone(),
        });
        state.next_seq += 1;
        state.prev = hash;
        Ok(())
    }
}

/// Why a log failed verification. Lines are numbered from 1.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// No events.
    #[error("the log is empty")]
    Empty,
    /// The last line has no newline: a write was cut short or the file was cut.
    #[error("the log ends with a partial record")]
    PartialRecord,
    /// A line is not a JSON object with a valid `chain`.
    #[error("line {0} is not a chained event")]
    Unchained(usize),
    /// A line belongs to another log.
    #[error("line {0} belongs to another log")]
    WrongLog(usize),
    /// A sequence number is missing or repeated.
    #[error("line {line}: expected seq {expected}, found {found}")]
    Gap {
        /// Line number.
        line: usize,
        /// Expected sequence number.
        expected: u64,
        /// Sequence number found.
        found: u64,
    },
    /// `prev` does not match the previous line: an earlier line was changed.
    #[error("line {0}: `prev` does not match the previous event")]
    BrokenLink(usize),
}

/// A log whose every link verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLog {
    /// Log identifier.
    pub log: String,
    hashes: Vec<String>,
}

impl VerifiedLog {
    /// The hash of the event with sequence number `seq`, if present.
    #[must_use]
    pub fn hash_at(&self, seq: u64) -> Option<&str> {
        usize::try_from(seq)
            .ok()
            .and_then(|i| self.hashes.get(i))
            .map(String::as_str)
    }

    /// Number of events.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// Whether there are no events (never true for a verified log).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The newest event.
    #[must_use]
    pub fn head(&self) -> ChainHead {
        ChainHead {
            log: self.log.clone(),
            seq: self.len().saturating_sub(1),
            hash: self.hashes.last().cloned().unwrap_or_default(),
        }
    }
}

/// Verifies every link of a whole log file.
///
/// # Errors
///
/// Returns the first [`ChainError`].
pub fn verify_log(bytes: &[u8]) -> Result<VerifiedLog, ChainError> {
    if bytes.is_empty() {
        return Err(ChainError::Empty);
    }
    let body = bytes.strip_suffix(b"\n").ok_or(ChainError::PartialRecord)?;
    let mut log: Option<String> = None;
    let mut hashes: Vec<String> = Vec::new();
    for (index, line) in body.split(|&b| b == b'\n').enumerate() {
        let number = index + 1;
        let link: ChainLink = serde_json::from_slice::<Value>(line)
            .ok()
            .and_then(|value| value.get("chain").cloned())
            .and_then(|chain| serde_json::from_value(chain).ok())
            .ok_or(ChainError::Unchained(number))?;
        let log_id = log.get_or_insert_with(|| link.log.clone());
        if &link.log != log_id {
            return Err(ChainError::WrongLog(number));
        }
        let expected = hashes.len() as u64;
        if link.seq != expected {
            return Err(ChainError::Gap {
                line: number,
                expected,
                found: link.seq,
            });
        }
        let expected_prev = hashes.last().cloned().unwrap_or_else(|| genesis(log_id));
        if link.prev != expected_prev {
            return Err(ChainError::BrokenLink(number));
        }
        hashes.push(line_hash(line));
    }
    Ok(VerifiedLog {
        log: log.unwrap_or_default(),
        hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, GatewayInfo, Verdict};
    use acf_protocol::{ActionName, RequestId, ResourceId, TaskId};

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    fn event(verdict: Verdict) -> AuditEvent {
        AuditEvent::new(
            EventKind::Decision,
            GatewayInfo {
                id: "gw".to_owned(),
                build: "development".to_owned(),
                deployment_profile: "development".to_owned(),
                config_digest: None,
            },
            RequestId::new("req-1").unwrap(),
            TaskId::new("task-1").unwrap(),
            ActionName::new("example.profile.get").unwrap(),
            ResourceId::new("example-api:development").unwrap(),
            verdict,
        )
    }

    async fn log_of(count: usize) -> (Shared, ChainedJsonSink) {
        let buffer = Shared::default();
        let sink = ChainedJsonSink::new(Box::new(buffer.clone())).unwrap();
        for _ in 0..count {
            sink.emit(&event(Verdict::Allowed)).await.unwrap();
        }
        (buffer, sink)
    }

    #[tokio::test]
    async fn a_written_log_verifies_and_matches_the_sink_head() {
        let (buffer, sink) = log_of(3).await;
        let verified = verify_log(&buffer.bytes()).unwrap();
        assert_eq!(verified.len(), 3);
        assert_eq!(verified.head(), sink.head().unwrap());
        assert_eq!(verified.log, sink.log());
        assert!(verified.log.starts_with("log-"));
    }

    #[tokio::test]
    async fn edits_deletions_and_cuts_are_detected() {
        let (buffer, _) = log_of(4).await;
        let text = String::from_utf8(buffer.bytes()).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        let edited = text.replacen("\"allowed\"", "\"denied\"", 1);
        assert_eq!(
            verify_log(edited.as_bytes()),
            Err(ChainError::BrokenLink(2))
        );

        let deleted = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]);
        assert!(matches!(
            verify_log(deleted.as_bytes()),
            Err(ChainError::Gap {
                line: 2,
                expected: 1,
                found: 2
            })
        ));

        assert_eq!(
            verify_log(&text.as_bytes()[..text.len() - 5]),
            Err(ChainError::PartialRecord)
        );

        let (other, _) = log_of(1).await;
        let spliced = format!(
            "{}{}\n",
            String::from_utf8(other.bytes()).unwrap(),
            lines[1]
        );
        assert_eq!(verify_log(spliced.as_bytes()), Err(ChainError::WrongLog(2)));

        // Dropping the tail still verifies: only a checkpoint can catch it.
        let truncated = format!("{}\n{}\n", lines[0], lines[1]);
        assert_eq!(verify_log(truncated.as_bytes()).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_restarted_sink_continues_the_same_log() {
        let (buffer, first) = log_of(2).await;
        let existing = buffer.bytes();
        let second = ChainedJsonSink::continuing(Box::new(buffer.clone()), &existing).unwrap();
        assert_eq!(second.log(), first.log());
        assert_eq!(second.head(), first.head());
        second.emit(&event(Verdict::Denied)).await.unwrap();
        let verified = verify_log(&buffer.bytes()).unwrap();
        assert_eq!(verified.len(), 3);

        let mut partial = buffer.bytes();
        partial.truncate(partial.len() - 1);
        assert!(ChainedJsonSink::continuing(Box::new(Shared::default()), &partial).is_err());
        assert!(
            ChainedJsonSink::continuing(Box::new(Shared::default()), b"{\"schema\":1}\n").is_err()
        );
    }

    #[tokio::test]
    async fn an_overdue_anchor_stops_the_sink() {
        let anchor = Arc::new(AnchorState::new(Duration::ZERO));
        let buffer = Shared::default();
        let sink = ChainedJsonSink::new(Box::new(buffer.clone()))
            .unwrap()
            .with_anchor(anchor.clone());
        // Nothing written yet: nothing to anchor.
        sink.emit(&event(Verdict::Allowed)).await.unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert!(matches!(
            sink.emit(&event(Verdict::Allowed)).await,
            Err(AuditError::Unanchored)
        ));
        anchor.anchored(0);
        sink.emit(&event(Verdict::Allowed)).await.unwrap();
        assert_eq!(verify_log(&buffer.bytes()).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_file_sink_reopens_and_continues() {
        let path = std::env::temp_dir().join(format!("acf-chain-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = ChainedJsonSink::open(&path).unwrap();
        sink.emit(&event(Verdict::Allowed)).await.unwrap();
        let log = sink.log();
        drop(sink);
        let sink = ChainedJsonSink::open(&path).unwrap();
        assert_eq!(sink.log(), log);
        sink.emit(&event(Verdict::Allowed)).await.unwrap();
        let verified = verify_log(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(verified.len(), 2);
        std::fs::remove_file(&path).unwrap();
    }
}
