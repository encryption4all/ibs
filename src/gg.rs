//! Galindo-Garcia Identity-based signatures (GG-IBS).
//!
//! - From: "[A Schnorr-Like Lightweight Identity-Based Signature Scheme](https://link.springer.com/chapter/10.1007/978-3-642-02384-2_9)", AfricaCrypt, 2009.
//!
//! The scheme is built on Curve25519 Ristretto, using crate [`curve25519_dalek`].
//!
//! Hash functions G and H are instantiated as follows:
//! - G = `SHAKE128` (with a 64-byte output).
//! - H = `SHA3_512`,
//!
//! The constant [Ristretto basepoint][`curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT`] is used as a generator.
//!
//! # Example
//!
//! ```
//! use ibs::{
//!     gg,
//!     gg::{Identity, PublicKey, SecretKey, Signer, UserSecretKey, Verifier},
//! };
//! use rand::prelude::*;
//!                                                                            
//! let mut rng = thread_rng();
//! let (pk, sk) = gg::setup(&mut rng);
//! let id = Identity::from("Johnny");
//!                                                                            
//! let usk_id = gg::keygen(&sk, &id, &mut rng);
//! let sig = Signer::new()
//!     .chain(b"The eagle has landed")
//!     .sign(&usk_id, &mut rng);
//!                                                                            
//! assert!(Verifier::new()
//!     .chain(b"The eagle ")
//!     .chain(b"has landed")
//!     .verify(&pk, &sig, &id));
//!                                                                            
//! assert!(!Verifier::new()
//!     .chain(b"The falcon has landed")
//!     .verify(&pk, &sig, &id));
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoPoint, scalar::Scalar, traits::VartimeMultiscalarMul,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128};

/// Size of a compressed public key.
pub const PK_BYTES: usize = 32;

/// Public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

/// Size of a compressed secret key.
pub const SK_BYTES: usize = 32;

/// Secret key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey(Scalar);

/// Size of a compressed [`UserSecretKey`].
pub const USK_BYTES: usize = 96;

/// User secret key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSecretKey {
    y: Scalar,
    gr: RistrettoPoint,
    id: Identity,
}

/// Size of a compressed [`Signature`].
pub const SIG_BYTES: usize = 96;

/// Signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    ga: RistrettoPoint,
    b: Scalar,
    gr: RistrettoPoint,
}

/// The size of the identity parameter.
pub const IDENTITY_BYTES: usize = 32;

/// Identity.
///
/// Uses a 32-byte internal representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity([u8; IDENTITY_BYTES]);

impl<T: AsRef<[u8]>> From<T> for Identity {
    fn from(b: T) -> Self {
        if b.as_ref().len() == IDENTITY_BYTES {
            Identity(b.as_ref().try_into().unwrap())
        } else {
            Identity(Sha3_256::digest(b.as_ref()).into())
        }
    }
}

// Helper function to compute H(g^r || id).
fn h_helper(gr: &RistrettoPoint, id: &Identity) -> Scalar {
    let mut h = Sha3_512::new();

    Digest::update(&mut h, gr.compress().as_bytes());
    Digest::update(&mut h, &id.0);

    Scalar::from_hash(h)
}

/// Create a master key pair.
pub fn setup<R: RngCore + CryptoRng>(r: &mut R) -> (PublicKey, SecretKey) {
    let z = Scalar::random(r);
    let gz = RISTRETTO_BASEPOINT_TABLE * &z;

    (PublicKey(gz), SecretKey(z))
}

/// Extract a signing key from the master secret key for a given identity.
pub fn keygen<R: RngCore + CryptoRng>(sk: &SecretKey, id: &Identity, r: &mut R) -> UserSecretKey {
    let r = Scalar::random(r);
    let gr = RISTRETTO_BASEPOINT_TABLE * &r;
    let y = r + sk.0 * h_helper(&gr, id);

    UserSecretKey { y, gr, id: *id }
}

/// Signer.
#[derive(Debug, Clone)]
pub struct Signer {
    g: Shake128,
}

impl Default for Signer {
    fn default() -> Self {
        Signer::new()
    }
}

impl Signer {
    /// Create a new signer.
    pub fn new() -> Self {
        Self {
            g: Shake128::default(),
        }
    }

    /// Sign additional message data.
    pub fn update(&mut self, m: impl AsRef<[u8]>) {
        self.g.update(m.as_ref());
    }

    /// Sign additional message data, in a chained manner.
    #[must_use]
    pub fn chain(mut self, m: impl AsRef<[u8]>) -> Self {
        self.g.update(m.as_ref());
        self
    }

    /// Create the signature. Call this after the message has been processed.
    pub fn sign<R: RngCore + CryptoRng>(mut self, usk: &UserSecretKey, r: &mut R) -> Signature {
        let a = Scalar::random(r);
        let ga = RISTRETTO_BASEPOINT_TABLE * &a;

        self.g.update(&usk.id.0);
        self.g.update(ga.compress().as_bytes());

        let mut out = [0u8; 64];
        self.g.finalize_xof_into(&mut out);

        let b = a + usk.y * Scalar::from_bytes_mod_order_wide(&out);

        Signature { ga, b, gr: usk.gr }
    }
}

/// Verifier.
#[derive(Debug, Clone)]
pub struct Verifier {
    g: Shake128,
}

impl Default for Verifier {
    fn default() -> Self {
        Verifier::new()
    }
}

impl Verifier {
    /// Create a new verifier instance.
    pub fn new() -> Self {
        Self {
            g: Shake128::default(),
        }
    }

    /// Verify additional message data.
    pub fn update(&mut self, m: impl AsRef<[u8]>) {
        self.g.update(m.as_ref());
    }

    /// Verify additional message data, in a chained manner.
    #[must_use]
    pub fn chain(mut self, m: impl AsRef<[u8]>) -> Self {
        self.g.update(m.as_ref());
        self
    }

    /// Verifies the signature.
    #[must_use]
    pub fn verify(mut self, pk: &PublicKey, sig: &Signature, id: &Identity) -> bool {
        self.g.update(&id.0);
        self.g.update(&sig.ga.compress().to_bytes());

        let c = h_helper(&sig.gr, id);

        let mut out = [0u8; 64];
        self.g.finalize_xof_into(&mut out);
        let d = Scalar::from_bytes_mod_order_wide(&out);

        let lhs = -sig.ga;
        let rhs = RistrettoPoint::vartime_multiscalar_mul(
            &[-sig.b, c * d, d],
            &[RISTRETTO_BASEPOINT_POINT, pk.0, sig.gr],
        );

        lhs.eq(&rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn default_setup() -> (PublicKey, UserSecretKey, Identity) {
        let (pk, sk) = setup(&mut OsRng);
        let mut rand_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut rand_bytes);
        let id = rand_bytes.into();
        let usk = keygen(&sk, &id, &mut OsRng);

        (pk, usk, id)
    }

    #[test]
    fn test_sign_verify() {
        let (pk, usk, id) = default_setup();

        let message = b"some identical message";
        let sig = Signer::new().chain(message).sign(&usk, &mut OsRng);

        assert!(Verifier::new().chain(message).verify(&pk, &sig, &id));
    }

    #[test]
    fn test_sign_wrong_message() {
        let (pk, usk, id) = default_setup();

        let sig = Signer::new().chain(b"some message").sign(&usk, &mut OsRng);
        assert!(!Verifier::new()
            .chain(b"some other message")
            .verify(&pk, &sig, &id));
    }

    #[test]
    fn test_sign_wrong_public_key() {
        let (_, usk1, id1) = default_setup();
        let (pk2, _, _) = default_setup();

        let message = b"some identical message";
        let sig = Signer::new().chain(message).sign(&usk1, &mut OsRng);

        assert!(!Verifier::new().chain(message).verify(&pk2, &sig, &id1));
    }

    #[test]
    fn test_sign_wrong_identity() {
        let (pk1, usk1, _) = default_setup();
        let (_, _, id2) = default_setup();

        let message = b"some identical message";
        let sig = Signer::new().chain(message).sign(&usk1, &mut OsRng);

        assert!(!Verifier::new().chain(message).verify(&pk1, &sig, &id2));
    }

    #[test]
    fn test_round() {
        // This test simulates a real-world scenario,
        // where all communicated messages are serialized/deserialized.

        let (pk, usk, id) = default_setup();

        // 1. PKG creates key pair and publishes the public key.
        let pk_serialized = bincode::serialize(&pk).unwrap();
        let usk_serialized = bincode::serialize(&usk).unwrap();

        // 2. A signer retrieves the public key and signs some message,
        // after which it sends the signature to the verifier.
        let pk_recovered: PublicKey = bincode::deserialize(&pk_serialized).unwrap();
        let usk_recovered = bincode::deserialize(&usk_serialized).unwrap();
        let sig = Signer::new()
            .chain(b"some message")
            .sign(&usk_recovered, &mut OsRng);
        let sig_serialized = bincode::serialize(&sig).unwrap();

        // 3. A verifier retrieves the signature from the signer and verifies it.
        let sig_recovered: Signature = bincode::deserialize(&sig_serialized).unwrap();

        assert!(Verifier::new()
            .chain(b"some message")
            .verify(&pk_recovered, &sig_recovered, &id));
    }

    #[test]
    fn test_clone_state() {
        let (pk, usk, id) = default_setup();

        let signer = Signer::new().chain(b"a");
        let sig2 = signer.clone().chain(b"b").sign(&usk, &mut OsRng);
        let sig1 = signer.sign(&usk, &mut OsRng);
        let verifier = Verifier::new().chain(b"a");
        assert!(verifier.clone().chain(b"b").verify(&pk, &sig2, &id));
        assert!(verifier.verify(&pk, &sig1, &id));
    }
}
