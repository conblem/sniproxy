use anyhow::{anyhow, Error};
use fast_socks5::client::{Config as SocksConfig, Socks5Stream};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{lookup_host, TcpStream};
use tracing_attributes::instrument;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

use crate::ARGS;

#[derive(Clone)]
pub(crate) struct UpstreamConnector {
    resolver: Option<Arc<TokioAsyncResolver>>,
}

impl UpstreamConnector {
    pub(crate) async fn new() -> Result<Self, Error> {
        let Some(dns) = &ARGS.dns else {
            return Ok(Self { resolver: None });
        };

        let dns_server = lookup_host(dns).await?.next();
        let Some(dns_server) = dns_server else {
            Err(anyhow!("No IP for DNS Server found"))?
        };
        let name_server_config = NameServerConfig::new(dns_server, Protocol::Udp);

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(name_server_config);

        let mut opts = ResolverOpts::default();
        opts.try_tcp_on_error = true;

        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);

        Ok(Self {
            resolver: Some(Arc::new(resolver)),
        })
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
        let Some(socks_host) = socks.host_str() else {
            Err(anyhow!("Invalid socks url"))?
        };
        let socks_addr = self.lookup_ip(socks_host).await?;

        let upstream = Socks5Stream::connect(
            (socks_addr, socks_port),
            target,
            port,
            SocksConfig::default(),
        )
        .await?;

        Ok(upstream.get_socket())
    }

    // add ipv6 support
    #[instrument(skip_all, ret, err)]
    async fn lookup_ip(&self, sni: &str) -> Result<Ipv4Addr, Error> {
        // If sni is already an ip we return early
        // this check is needed because ipv4_lookup does not support ip addresses
        // and will actually query the dns with ip addr
        if let Ok(ip) = sni.parse::<Ipv4Addr>() {
            return Ok(ip);
        }

        if let Some(resolver) = &self.resolver {
            let lookup = resolver.ipv4_lookup(sni).await?;

            let record = lookup.iter().next().ok_or_else(|| anyhow!("No IP found"))?;

            return Ok(Ipv4Addr::from(record.octets()));
        }

        // this method requires a port we ignore afterward
        let addr = lookup_host((sni, 80))
            .await?
            .filter_map(|addr| match addr {
                SocketAddr::V4(addr) => Some(addr),
                _ => None,
            })
            .next();

        let Some(addr) = addr else {
            Err(anyhow!("No IP found"))?
        };

        Ok(*addr.ip())
    }
}
