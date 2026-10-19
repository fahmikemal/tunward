use crate::management::registry::FleetRegistry;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run_management_server(bind_addr: SocketAddr, registry: FleetRegistry) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("Tunward Management REST API listening on http://{bind_addr}");

    let auto_server = auto::Builder::new(TokioExecutor::new());

    loop {
        let (stream, _remote_peer) = match listener.accept().await {
            Ok(val) => val,
            Err(err) => {
                error!("Management API accept error: {err}");
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let reg = registry.clone();
        let server = auto_server.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let reg = reg.clone();
                async move { Ok::<_, Infallible>(handle_request(req, reg).await) }
            });

            if let Err(err) = server.serve_connection_with_upgrades(io, service).await {
                let _ = err;
            }
        });
    }
}

async fn handle_request<B: hyper::body::Body>(req: Request<B>, registry: FleetRegistry) -> Response<Full<Bytes>> {
    let method = req.method();
    let path = req.uri().path();

    match (method, path) {
        (&Method::GET, "/healthz") => {
            let health = registry.health();
            let json = serde_json::to_vec(&health).unwrap_or_default();
            json_response(StatusCode::OK, json)
        }
        (&Method::GET, "/api/v1/clients") => {
            let clients = registry.list_clients();
            let json = serde_json::to_vec(&clients).unwrap_or_default();
            json_response(StatusCode::OK, json)
        }
        (&Method::GET, path) if path.starts_with("/api/v1/clients/") => {
            let client_id = &path["/api/v1/clients/".len()..];
            if let Some(client) = registry.get_client(client_id) {
                let json = serde_json::to_vec(&client).unwrap_or_default();
                json_response(StatusCode::OK, json)
            } else {
                json_response(StatusCode::NOT_FOUND, b"{\"error\":\"Client not found\"}".to_vec())
            }
        }
        (&Method::GET, "/api/v1/sessions") => {
            let sessions = registry.list_sessions();
            let json = serde_json::to_vec(&sessions).unwrap_or_default();
            json_response(StatusCode::OK, json)
        }
        _ => json_response(StatusCode::NOT_FOUND, b"{\"error\":\"Route not found\"}".to_vec()),
    }
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;

    #[tokio::test]
    async fn test_management_api_routes() {
        let registry = FleetRegistry::new();
        let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        registry.register_client("kiosk-test".to_string(), peer);

        // Test GET /healthz
        let req = Request::builder().uri("/healthz").body(Empty::<Bytes>::new()).unwrap();
        let resp = handle_request(req, registry.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Test GET /api/v1/clients
        let req = Request::builder()
            .uri("/api/v1/clients")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = handle_request(req, registry.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Test GET /api/v1/clients/kiosk-test
        let req = Request::builder()
            .uri("/api/v1/clients/kiosk-test")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = handle_request(req, registry.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Test GET /api/v1/clients/non-existent
        let req = Request::builder()
            .uri("/api/v1/clients/non-existent")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = handle_request(req, registry.clone()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Test 404 Not Found
        let req = Request::builder().uri("/unknown").body(Empty::<Bytes>::new()).unwrap();
        let resp = handle_request(req, registry.clone()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
