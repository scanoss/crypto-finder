// Lookalikes: catalog names that come from no framework crate.
use async_trait::async_trait;
use futures::TryFutureExt;
use sha2::{Digest, Sha256};

mod cache {
    pub fn get<F: Fn() -> String>(load: F) -> String {
        load()
    }

    pub fn service_fn<F>(f: F) -> F {
        f
    }
}

mod macros {
    pub use std::prelude::v1::test as get;
}

use macros::get;

// #[get] from a local module, not actix_web or rocket.
#[get("/x")]
fn not_a_route() -> String {
    format!("{:x}", Sha256::digest(b"lookalike-attribute"))
}

fn cached() -> String {
    format!("{:x}", Sha256::digest(b"lookalike-get"))
}

fn wrapped() -> String {
    format!("{:x}", Sha256::digest(b"lookalike-service-fn"))
}

async fn then_step(_v: u8) -> Result<String, ()> {
    Ok(format!("{:x}", Sha256::digest(b"lookalike-and-then")))
}

// get, service_fn and and_then from no framework crate.
pub fn warm() {
    let _ = cache::get(cached);
    let _ = cache::service_fn(wrapped);
    let _ = futures::future::ready(Ok::<u8, ()>(1)).and_then(then_step);
}

pub trait Store {
    fn put(&self) -> String;
}

pub struct Db;

// async_trait from the async_trait crate, not tonic's re-export.
#[async_trait]
impl Store for Db {
    fn put(&self) -> String {
        format!("{:x}", Sha256::digest(b"lookalike-async-trait"))
    }
}

fn orphan() -> String {
    format!("{:x}", Sha256::digest(b"orphan"))
}
