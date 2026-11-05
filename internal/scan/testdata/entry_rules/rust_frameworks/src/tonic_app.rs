use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("keys");
}

use pb::keys_server::Keys;
use pb::{RotateReply, RotateRequest};

#[derive(Default)]
pub struct KeyService;

#[tonic::async_trait]
impl Keys for KeyService {
    async fn rotate(&self, request: Request<RotateRequest>) -> Result<Response<RotateReply>, Status> {
        let digest = Sha256::digest(request.into_inner().key.as_bytes());
        let _check = Sha256::digest(b"tonic-rotate");
        Ok(Response::new(RotateReply { fingerprint: format!("{:x}", digest) }))
    }
}
