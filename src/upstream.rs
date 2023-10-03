use anyhow::{anyhow, Error};
use fast_socks5::client::{Config as SocksConfig, Socks5Stream};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing_attributes::instrument;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

use crate::ARGS;

#[derive(Clone)]
pub(crate) struct UpstreamConnector {
    resolver: Arc<TokioAsyncResolver>,
}

impl UpstreamConnector {
    pub(crate) fn new(upstream_connector: TokioAsyncResolver) -> Self {
        Self {
            resolver: Arc::new(upstream_connector),
        }
    }

    #[instrument(skip_all, fields(port = port), err)]
    pub(crate) async fn connect(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        match ARGS.socks {
            Some(ref socks) => self.upstream_socks(sni, port, socks).await,
            None => self.upstream_direct(sni, port).await,
        }
    }

    #[instrument(skip_all, err)]
    async fn upstream_direct(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        let target = self.lookup_ip(sni).await?;

        Ok(TcpStream::connect((target, port)).await?)
    }

    #[instrument(skip_all, fields(socks = %socks), err)]
    async fn upstream_socks(&self, sni: &str, port: u16, socks: &Url) -> Result<TcpStream, Error> {
        let target = match socks.scheme() {
            "socks5" => self.lookup_ip(sni).await?.to_string(),
            "socks5h" => sni.to_string(),
            _ => Err(anyhow!("Invalid scheme for socks"))?,
        };

        let socks_port = socks.port().unwrap_or(1080);
        let socks_host = match socks.host_str() {
            Some(socks_host) => (socks_host, socks_port),
            None => Err(anyhow!("Invalid socks url"))?,
        };

        let upstream =
            Socks5Stream::connect(socks_host, target, port, SocksConfig::default()).await?;

        Ok(upstream.get_socket())
    }

    // add ipv6 support
    #[instrument(skip_all, ret, err)]
    async fn lookup_ip(&self, sni: &str) -> Result<Ipv4Addr, Error> {
        let lookup = self.resolver.ipv4_lookup(sni).await?;

        let record = lookup.iter().next().ok_or(anyhow!("No IP found"))?;

        Ok(Ipv4Addr::from(record.octets()))
    }
}
