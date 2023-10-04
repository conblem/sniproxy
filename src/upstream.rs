use anyhow::{anyhow, Error};
use fast_socks5::client::{Config as FastSocksConfig, Socks5Stream};
use fast_socks5::util::target_addr::ToTargetAddr;
use fast_socks5::Socks5Command;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{lookup_host, TcpStream, ToSocketAddrs};
use tracing_attributes::instrument;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::lookup::{Ipv4Lookup, Ipv6Lookup};
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

use crate::ARGS;

#[derive(Debug, Clone)]
enum SocksDnsResolution {
    Local,
    Socks,
}

#[derive(Debug)]
struct SocksConfig {
    dns_resolution: SocksDnsResolution,
    socks_addr: LookupResultWithPort,
}

#[derive(Clone)]
pub(crate) struct UpstreamConnector {
    resolver: Option<Arc<TokioAsyncResolver>>,
    socks_config: Option<Arc<SocksConfig>>,
}

impl UpstreamConnector {
    pub(crate) async fn new() -> Result<Self, Error> {
        let resolver = match &ARGS.dns {
            Some(dns) => Some(Self::create_resolver(dns).await?),
            None => None,
        };

        let mut this = Self {
            resolver: resolver.map(Arc::new),
            socks_config: None,
        };

        let Some(socks) = &ARGS.socks else {
            return Ok(this);
        };

        let socks_config = this.socks_config(socks).await?;
        this.socks_config = Some(Arc::new(socks_config));

        Ok(this)
    }

    async fn socks_config(&self, socks: &Url) -> Result<SocksConfig, Error> {
        let dns_resolution = match socks.scheme() {
            "socks5" => SocksDnsResolution::Local,
            "socks5h" => SocksDnsResolution::Socks,
            _ => Err(anyhow!("Invalid scheme for socks"))?,
        };

        let socks_port = socks.port().unwrap_or(1080);
        let Some(socks_host) = socks.host_str() else {
            Err(anyhow!("Invalid socks url"))?
        };
        let socks_addr = self.lookup_ip(socks_host).await?.with_port(socks_port);

        Ok(SocksConfig {
            dns_resolution,
            socks_addr,
        })
    }

    async fn create_resolver(dns: &str) -> Result<TokioAsyncResolver, Error> {
        let dns_server = lookup_host(dns).await?.next();
        let Some(dns_server) = dns_server else {
            Err(anyhow!("No IP for DNS Server found"))?
        };
        let name_server_config = NameServerConfig::new(dns_server, Protocol::Udp);

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(name_server_config);

        let mut opts = ResolverOpts::default();
        opts.try_tcp_on_error = true;

        Ok(TokioAsyncResolver::tokio(resolver_config, opts))
    }

    #[instrument(skip_all, fields(port = port), err)]
    pub(crate) async fn connect(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        match &self.socks_config {
            Some(socks_config) => self.upstream_socks(sni, port, socks_config).await,
            None => self.upstream_direct(sni, port).await,
        }
    }

    #[instrument(skip_all, err)]
    async fn upstream_direct(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        let target = self.lookup_ip(sni).await?.with_port(port);

        let upstream_conn = happy_eyeballs::tokio::connect(target.addrs()).await?;

        Ok(upstream_conn)
    }

    // maybe add retry logic for socks if first target addr fails
    #[instrument(skip_all, fields(socks_config = ?socks_config), err)]
    async fn upstream_socks(
        &self,
        sni: &str,
        port: u16,
        socks_config: &SocksConfig,
    ) -> Result<TcpStream, Error> {
        let target = match socks_config.dns_resolution {
            SocksDnsResolution::Local => self
                .lookup_ip(sni)
                .await?
                .with_port(port)
                .first()
                .ok_or_else(|| anyhow!("No IP found"))?
                .to_target_addr()?,
            SocksDnsResolution::Socks => (sni, port).to_target_addr()?,
        };

        let upstream_conn = happy_eyeballs::tokio::connect(socks_config.socks_addr.addrs()).await?;

        let mut upstream =
            Socks5Stream::use_stream(upstream_conn, None, FastSocksConfig::default()).await?;
        upstream.request(Socks5Command::TCPConnect, target).await?;

        Ok(upstream.get_socket())
    }

    #[instrument(skip_all, ret, err)]
    async fn lookup_ip(&self, sni: &str) -> Result<LookupResult, Error> {
        // If sni is already an ip we return early
        // this check is needed because ipv4_lookup does not support ip addresses
        // and will actually query the dns with ip addr
        if let Ok(ip) = sni.parse::<IpAddr>() {
            return Ok(LookupResult::Static(ip));
        }

        if let Some(resolver) = &self.resolver {
            let ips = match (ARGS.ipv4, ARGS.ipv6) {
                (true, false) => resolver.ipv4_lookup(sni).await?.into(),
                (false, true) => resolver.ipv6_lookup(sni).await?.into(),
                (true, true) => resolver.lookup_ip(sni).await?.into(),
                (false, false) => Err(anyhow!("Atleast ipv4 or ipv6 have to be enabled"))?,
            };

            return Ok(ips);
        }

        // this method requires a port we ignore afterward
        let addr = lookup_host((sni, 80)).await?.collect::<Vec<_>>().into();

        Ok(addr)
    }
}

// todo: test this
// should be quite easy
#[derive(Debug)]
enum LookupResult {
    Ipv4(Ipv4Lookup),
    Ipv6(Ipv6Lookup),
    DualStack(LookupIp),
    Static(IpAddr),
    Tokio(Vec<SocketAddr>),
}

impl From<Vec<SocketAddr>> for LookupResult {
    fn from(value: Vec<SocketAddr>) -> Self {
        Self::Tokio(value)
    }
}

impl From<IpAddr> for LookupResult {
    fn from(value: IpAddr) -> Self {
        Self::Static(value)
    }
}
impl From<Ipv4Lookup> for LookupResult {
    fn from(value: Ipv4Lookup) -> Self {
        Self::Ipv4(value)
    }
}

impl From<Ipv6Lookup> for LookupResult {
    fn from(value: Ipv6Lookup) -> Self {
        Self::Ipv6(value)
    }
}

impl From<LookupIp> for LookupResult {
    fn from(value: LookupIp) -> Self {
        Self::DualStack(value)
    }
}

impl LookupResult {
    fn with_port(self, port: u16) -> LookupResultWithPort {
        let socket_addrs = match self {
            Self::Ipv4(lookup) => lookup.iter().map(|ip| (ip.octets(), port).into()).collect(),
            Self::Ipv6(lookup) => lookup.iter().map(|ip| (ip.octets(), port).into()).collect(),
            Self::DualStack(lookup) => lookup.iter().map(|ip| (ip, port).into()).collect(),
            Self::Static(ip) => vec![(ip, port).into()],
            Self::Tokio(mut ips) => {
                for ip in &mut ips {
                    ip.set_port(port)
                }
                ips
            }
        };
        LookupResultWithPort { socket_addrs }
    }
}

#[derive(Debug)]
struct LookupResultWithPort {
    socket_addrs: Vec<SocketAddr>,
}

impl LookupResultWithPort {
    fn addrs(&self) -> impl ToSocketAddrs + '_ {
        &self.socket_addrs[..]
    }

    fn first(&self) -> Option<SocketAddr> {
        self.socket_addrs.first().copied()
    }
}
