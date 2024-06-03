use hyper::client::connect::HttpConnector;
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use rustls::ServerConfig;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use webpki_roots::TLS_SERVER_ROOTS;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use rustls_pemfile::{certs, rsa_private_keys};

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("Intercepted request: {:?}", req);

    let client = Client::new();
    let resp = client.request(req).await?;
    Ok(resp)
}

async fn handle_connection(stream: tokio::net::TcpStream, tls_acceptor: Arc<TlsAcceptor>) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let is_tls = peer_addr.port() == 443;
    if is_tls {
        let stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        if let Err(err) = Http::new().serve_connection(stream, service_fn(handle_request)).await {
            eprintln!("Error serving connection: {:?}", err);
        }
    } else {
        if let Err(err) = Http::new().serve_connection(stream, service_fn(handle_request)).await {
            eprintln!("Error serving connection: {:?}", err);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:8080".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    let certs = load_certs("cert.pem")?;
    let key = load_private_key("key.pem")?;
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            handle_connection(stream, tls_acceptor).await;
        });
    }
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error + Send + Sync>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = certs(&mut reader)
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error + Send + Sync>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let keys = rsa_private_keys(&mut reader);

    Ok(PrivateKey(keys[0].clone()))
}
