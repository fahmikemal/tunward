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
    anyhow::ensure!(
        bind_addr.ip().is_loopback(),
        "management API must bind to loopback; expose it through an authenticated TLS proxy"
    );
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
            let status = if health.status == "healthy" {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let json = serde_json::to_vec(&health).unwrap_or_default();
            json_response(status, json)
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
        (&Method::GET, "/api/v1/connections") => json_response(
            StatusCode::OK,
            serde_json::to_vec(&registry.list_connections()).unwrap_or_default(),
        ),
        (&Method::GET, "/api/v1/devices") => {
            let (limit, after) = match inventory_query(req.uri().query()) {
                Ok(query) => query,
                Err(_) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        b"{\"error\":\"Invalid inventory pagination\"}".to_vec(),
                    );
                }
            };
            match registry.list_devices(limit, after).await {
                Ok(page) => json_response(StatusCode::OK, serde_json::to_vec(&page).unwrap_or_default()),
                Err(err) => {
                    error!("Cannot read device inventory: {err:#}");
                    json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        b"{\"error\":\"Inventory unavailable\"}".to_vec(),
                    )
                }
            }
        }
        (&Method::GET, path) if path.starts_with("/api/v1/devices/") => {
            let identity = match urlencoding::decode(&path["/api/v1/devices/".len()..]) {
                Ok(identity) if !identity.is_empty() => identity.into_owned(),
                _ => {
                    return json_response(StatusCode::BAD_REQUEST, b"{\"error\":\"Invalid device identity\"}".to_vec());
                }
            };
            match registry.get_device(identity).await {
                Ok(Some(device)) => json_response(StatusCode::OK, serde_json::to_vec(&device).unwrap_or_default()),
                Ok(None) => json_response(StatusCode::NOT_FOUND, b"{\"error\":\"Device not found\"}".to_vec()),
                Err(err) => {
                    error!("Cannot read device inventory: {err:#}");
                    json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        b"{\"error\":\"Inventory unavailable\"}".to_vec(),
                    )
                }
            }
        }
        _ => json_response(StatusCode::NOT_FOUND, b"{\"error\":\"Route not found\"}".to_vec()),
    }
}

fn inventory_query(query: Option<&str>) -> anyhow::Result<(usize, String)> {
    let mut limit = None;
    let mut after = None;
    for pair in query.unwrap_or("").split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or_else(|| anyhow::anyhow!("invalid query"))?;
        let value = urlencoding::decode(value)?;
        match key {
            "limit" if limit.is_none() => {
                let value = value.parse::<usize>()?;
                anyhow::ensure!((1..=1000).contains(&value), "invalid page limit");
                limit = Some(value);
            }
            "after" if after.is_none() => after = Some(value.into_owned()),
            _ => anyhow::bail!("unknown or duplicate pagination argument"),
        }
    }
    Ok((limit.unwrap_or(100), after.unwrap_or_default()))
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CACHE_CONTROL, "no-store")
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
