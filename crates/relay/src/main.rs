//! Snailfish relay.
//!
//! The relay orders records and enforces quotas. It verifies records with the
//! same `snailfish-protocol` crate as the engine, and it holds no key that
//! decrypts app data (DESIGN.md "Crypto boundary").

use snailfish_protocol as _;

fn main() {
    // M2 adds the HTTP server.
}
