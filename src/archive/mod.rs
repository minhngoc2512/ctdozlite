//! Tiered message/media archive on S3-compatible object storage (ADR-0004).
//!
//! Message rows and media files of each account are uploaded as immutable objects
//! (optionally encrypted), local copies can then be pruned by a retention policy, and
//! older segments are fetched back on demand. Everything here runs on the worker or the
//! blocking pool, never on the UI thread (INV-3).

pub mod envelope;
pub mod keys;
pub mod config;
pub mod s3;
pub mod db;
pub mod layout;
pub mod engine;
