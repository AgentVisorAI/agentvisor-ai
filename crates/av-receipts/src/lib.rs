//! Receipts: RFC 8785 (JCS) canonicalization, session event-chain hashing, and
//! Ed25519-signed, offline-verifiable Receipts (brief Module G).
//!
//! Signing discipline per the brief §2: a Receipt is finalized **once, at
//! session close**, asynchronously — never per streaming chunk. Verification
//! requires only the receipt JSON and the signer's public key (or a keyring
//! holding it): no Bridge connectivity, no AgentVisor AI code beyond this crate.

pub mod chain;
pub mod jcs;
pub mod keys;
pub mod receipt;

pub use chain::EventChain;
pub use jcs::{canonicalize, JcsError};
pub use keys::{Ed25519Signer, KeyError, Keyring, Signer};
pub use receipt::{
    CostSummary, Receipt, ReceiptBody, ReceiptError, ReceiptSubject, ToolCallSummary, RECEIPT_VERSION,
};
