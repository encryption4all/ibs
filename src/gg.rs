//! Galindo-Garcia Identity-based signatures (GG-IBS).
//!
//! - From: "[A Schnorr-Like Lightweight Identity-Based Signature Scheme](https://link.springer.com/chapter/10.1007/978-3-642-02384-2_9)", AfricaCrypt, 2009.
//!
//! The scheme is built on Curve25519 Ristretto, using crate [`curve25519_dalek`].
//!
//! Hash functions G and H are instantiated as follows:
//! - G = `SHA3_512`,
//! - H = `SHAKE128` (with a 64-byte output).
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
//! let sig = Signer::new(&usk_id, &mut rng)
//!     .chain(b"The eagle has landed")
//!     .sign();
//!                                                                            
//! assert!(Verifier::new(&pk, &sig, &id)
//!     .chain(b"The eagle ")
//!     .chain(b"has landed")
//!     .verify());
//!                                                                            
//! assert!(!Verifier::new(&pk, &sig, &id)
//!     .chain(b"The falcon has landed")
//!     .verify());
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoPoint, scalar::Scalar, traits::VartimeMultiscalarMul,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128};

/// Public key.
pub type PublicKey = RistrettoPoint;

/// Secret key.
pub type SecretKey = Scalar;

/// User secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecretKey {
    y: Scalar,
    gr: RistrettoPoint,
    id: Identity,
}

/// Signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    ga: RistrettoPoint,
    b: Scalar,
    gr: RistrettoPoint,
}

/// Identity.
///
/// Uses a 32-byte internal representation.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Identity([u8; 32]);

impl<T: AsRef<[u8]>> From<T> for Identity {
    fn from(b: T) -> Self {
        Identity(Sha3_256::digest(b.as_ref()).into())
    }
}

// Computes SHAKE128 with a 64-byte output.
fn shake128_64(input: impl AsRef<[u8]>) -> [u8; 64] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut res = [0u8; 64];
    reader.read(&mut res);

    res
}

// Helper function to compute H(g^r || id).
fn h_helper(gr: &RistrettoPoint, id: &Identity) -> Scalar {
    let mut h_input = [0u8; 64];
    h_input[0..32].copy_from_slice(gr.compress().as_bytes());
    h_input[32..64].copy_from_slice(&id.0);
    let h = shake128_64(h_input);

    Scalar::from_bytes_mod_order_wide(&h)
}

/// Create a master key pair.
pub fn setup<R: RngCore + CryptoRng>(r: &mut R) -> (PublicKey, SecretKey) {
    let z = Scalar::random(r);
    let gz = &RISTRETTO_BASEPOINT_TABLE * &z;

    (gz, z)
}

/// Extract a signing key from the master secret key for a given identity.
pub fn keygen<R: RngCore + CryptoRng>(sk: &SecretKey, id: &Identity, r: &mut R) -> UserSecretKey {
    let r = Scalar::random(r);
    let gr = &RISTRETTO_BASEPOINT_TABLE * &r;
    let y = r + sk * h_helper(&gr, id);

    UserSecretKey { y, gr, id: *id }
}

/// Signer.
#[derive(Debug)]
pub struct Signer {
    usk: UserSecretKey,
    a: Scalar,
    ga: RistrettoPoint,
    g: Sha3_512,
}

impl Signer {
    /// Create a new signer.
    pub fn new<R: RngCore + CryptoRng>(usk: &UserSecretKey, r: &mut R) -> Self {
        let a = Scalar::random(r);
        let ga = &RISTRETTO_BASEPOINT_TABLE * &a;

        let mut g = Sha3_512::new();
        g.update(usk.id.0);
        g.update(ga.compress().as_bytes());

        Self {
            usk: usk.clone(),
            a,
            ga,
            g,
        }
    }

    /// Sign additional message data.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.g.update(data);
    }

    /// Sign additional message data, in a chained manner.
    #[must_use]
    pub fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.g.update(data);
        self
    }

    /// Create the signature. Call this after the message has been processed.
    pub fn sign(self) -> Signature {
        let b = self.a + self.usk.y * Scalar::from_hash(self.g);

        Signature {
            ga: self.ga,
            b,
            gr: self.usk.gr,
        }
    }
}

/// Verifier.
#[derive(Debug)]
pub struct Verifier {
    pk: PublicKey,
    sig: Signature,
    c: Scalar,
    g: Sha3_512,
}

impl Verifier {
    /// Create a new verifier instance.
    pub fn new(pk: &PublicKey, sig: &Signature, id: &Identity) -> Self {
        let c = h_helper(&sig.gr, id);

        let mut g = Sha3_512::new();
        g.update(id.0);
        g.update(sig.ga.compress().to_bytes());

        Self {
            pk: *pk,
            sig: sig.clone(),
            c,
            g,
        }
    }

    /// Add message data to be verified.
    pub fn update(&mut self, m: impl AsRef<[u8]>) {
        self.g.update(&m);
    }

    /// Add message data to be verified, in a chained manner.
    #[must_use]
    pub fn chain(mut self, m: impl AsRef<[u8]>) -> Self {
        self.update(&m);
        self
    }

    /// Verifies the signature.
    pub fn verify(self) -> bool {
        let d = Scalar::from_hash(self.g);

        let lhs = -self.sig.ga;
        let rhs = RistrettoPoint::vartime_multiscalar_mul(
            &[-self.sig.b, self.c * d, d],
            &[RISTRETTO_BASEPOINT_POINT, self.pk, self.sig.gr],
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
        let sig = Signer::new(&usk, &mut OsRng).chain(message).sign();

        assert!(Verifier::new(&pk, &sig, &id).chain(message).verify());
    }

    #[test]
    fn test_sign_wrong_message() {
        let (pk, usk, id) = default_setup();

        let sig = Signer::new(&usk, &mut OsRng).chain(b"some message").sign();
        assert!(!Verifier::new(&pk, &sig, &id)
            .chain(b"some other message")
            .verify());
    }

    #[test]
    fn test_sign_wrong_public_key() {
        let (_, usk1, id1) = default_setup();
        let (pk2, _, _) = default_setup();

        let message = b"some identical message";
        let sig = Signer::new(&usk1, &mut OsRng).chain(message).sign();

        assert!(!Verifier::new(&pk2, &sig, &id1).chain(message).verify());
    }

    #[test]
    fn test_sign_wrong_identity() {
        let (pk1, usk1, _) = default_setup();
        let (_, _, id2) = default_setup();

        let message = b"some identical message";
        let sig = Signer::new(&usk1, &mut OsRng).chain(message).sign();

        assert!(!Verifier::new(&pk1, &sig, &id2).chain(message).verify());
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
        let sig = Signer::new(&usk_recovered, &mut OsRng)
            .chain(b"some message")
            .sign();
        let sig_serialized = bincode::serialize(&sig).unwrap();

        // 3. A verifier retrieves the signature from the signer and verifies it.
        let sig_recovered: Signature = bincode::deserialize(&sig_serialized).unwrap();

        assert!(Verifier::new(&pk_recovered, &sig_recovered, &id)
            .chain(b"some message")
            .verify());
    }
}
