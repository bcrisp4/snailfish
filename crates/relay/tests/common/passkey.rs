//! A software passkey authenticator for the tests: ES256, attestation
//! "none", with user presence and user verification. It makes the browser
//! side of a `WebAuthn` ceremony from the `webauthn-rs` options, so the relay
//! runs its real checks.
#![allow(dead_code)]

use std::collections::BTreeMap;

use data_encoding::BASE64URL_NOPAD;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub struct SoftPasskey {
    key: EcKey<Private>,
    pub cred_id: Vec<u8>,
    counter: u32,
    pub origin: String,
    pub rp_id: String,
}

fn b64(b: &[u8]) -> String {
    BASE64URL_NOPAD.encode(b)
}

impl SoftPasskey {
    pub fn new(origin: &str, rp_id: &str) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut id = vec![0u8; 16];
        openssl::rand::rand_bytes(&mut id).unwrap();
        Self {
            key: EcKey::generate(&group).unwrap(),
            cred_id: id,
            counter: 0,
            origin: origin.to_owned(),
            rp_id: rp_id.to_owned(),
        }
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    fn cose_key(&self) -> Vec<u8> {
        let group = self.key.group();
        let mut ctx = BigNumContext::new().unwrap();
        let point = self
            .key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let mut m = BTreeMap::new();
        m.insert(Cbor::Integer(1), Cbor::Integer(2));
        m.insert(Cbor::Integer(3), Cbor::Integer(-7));
        m.insert(Cbor::Integer(-1), Cbor::Integer(1));
        m.insert(Cbor::Integer(-2), Cbor::Bytes(point[1..33].to_vec()));
        m.insert(Cbor::Integer(-3), Cbor::Bytes(point[33..65].to_vec()));
        serde_cbor_2::to_vec(&Cbor::Map(m)).unwrap()
    }

    /// The credential for the options of a registration start response.
    pub fn create(&mut self, start: &Value) -> Value {
        let challenge = start["options"]["publicKey"]["challenge"].as_str().unwrap();
        let cd = self.client_data("webauthn.create", challenge);
        let mut auth = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth.push(0x45); // UP, UV, AT
        auth.extend_from_slice(&self.counter.to_be_bytes());
        auth.extend_from_slice(&[0; 16]);
        auth.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
        auth.extend_from_slice(&self.cred_id);
        auth.extend_from_slice(&self.cose_key());
        let mut att = BTreeMap::new();
        att.insert(Cbor::Text("fmt".into()), Cbor::Text("none".into()));
        att.insert(Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new()));
        att.insert(Cbor::Text("authData".into()), Cbor::Bytes(auth));
        let att = serde_cbor_2::to_vec(&Cbor::Map(att)).unwrap();
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {"attestationObject": b64(&att), "clientDataJSON": b64(&cd)},
            "extensions": {}
        })
    }

    /// The assertion for the options of a sign-in start response.
    pub fn get(&mut self, start: &Value) -> Value {
        let challenge = start["options"]["publicKey"]["challenge"].as_str().unwrap();
        let cd = self.client_data("webauthn.get", challenge);
        self.counter += 1;
        let mut auth = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth.push(0x05); // UP, UV
        auth.extend_from_slice(&self.counter.to_be_bytes());
        let mut msg = auth.clone();
        msg.extend_from_slice(&Sha256::digest(&cd));
        let pkey = PKey::from_ec_key(self.key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(&msg).unwrap();
        let sig = signer.sign_to_vec().unwrap();
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {"authenticatorData": b64(&auth), "clientDataJSON": b64(&cd), "signature": b64(&sig), "userHandle": null},
            "extensions": {}
        })
    }
}
