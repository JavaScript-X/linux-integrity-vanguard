//! Shared domain types for Linux Integrity Vanguard.
//!
//! This crate stays platform-independent so protocol and policy behavior can be
//! exercised without access to Linux or privileged telemetry.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod policy;
pub mod protocol;
pub mod wire;
