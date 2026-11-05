use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde_json::Value;
use sha2::{Digest, Sha256};

async fn function_handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let digest = Sha256::digest(b"lambda-runtime");
    Ok(serde_json::json!({ "id": event.context.request_id, "digest": format!("{:x}", digest) }))
}

async fn http_handler(_req: lambda_http::Request) -> Result<String, Error> {
    Ok(format!("{:x}", Sha256::digest(b"lambda-http")))
}

pub async fn start() -> Result<(), Error> {
    run(service_fn(function_handler)).await
}

pub async fn start_http() -> Result<(), Error> {
    lambda_http::run(lambda_http::service_fn(http_handler)).await
}
