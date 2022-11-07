//! Identity-based signatures (IBS) library.
//!
//! Currently this library contains only _one_ IBS scheme: Galindo-Garcia (GG).

#![no_std]
#![deny(missing_debug_implementations, missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod gg;
