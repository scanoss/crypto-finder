use crate::crypto::{fingerprint, sign as hmac_sign};

pub async fn digest(body: String) -> String {
    fingerprint(body.as_bytes())
}

pub async fn sign(body: String) -> String {
    hmac_sign(b"server-key", body.as_bytes())
}
