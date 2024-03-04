use anyhow::{anyhow, Error, Result};
use fast_socks5::client::{Config as FastSocksConfig, Socks5Stream};
use fast_socks5::util::target_addr::{TargetAddr, ToTargetAddr};
use fast_socks5::Socks5Command;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::{GenericConnector, RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::proto::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::proto::TokioTime;
use hickory_resolver::{AsyncResolver, TokioHandle};
use lookup_result::{LookupResult, LookupResultWithPort};
use std::fmt::Debug;
use std::future::{ready, Future};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tracing::{info, instrument};
use url::Url;

use crate::ARGS;

mod lookup_result;

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
    resolver: UpstreamResolver,
    socks: Option<SocksUpstreamConnector>,
}

impl UpstreamConnector {
    pub(crate) async fn new() -> Result<Self, Error> {
        let socks = match &ARGS.socks {
            Some(socks) => Some(SocksUpstreamConnector::new(socks).await?),
            None => None,
        };
        let runtime_provider = RuntimeProviderWithSocks::new(socks.clone());

        Ok(Self {
            resolver: UpstreamResolver::new(runtime_provider).await?,
            socks,
        })
    }

    #[instrument(skip_all, fields(port = port), err)]
    pub(crate) async fn connect(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        let is_excluded = &ARGS.socks_exclude.iter().find(|exclude| sni.eq(*exclude));
        if is_excluded.is_some() {
            info!("Excluded from socks");
            return self.upstream_direct(sni, port).await;
        }
        let Some(socks) = &self.socks else {
            return self.upstream_direct(sni, port).await;
        };

        let target = match socks.config().dns_resolution {
            SocksDnsResolution::Local => self
                .resolver
                .lookup_socketaddr(sni, port)
                .await?
                .to_target_addr()?,
            SocksDnsResolution::Socks => (sni, port).to_target_addr()?,
        };
        return socks.connect(target).await;
    }

    #[instrument(skip_all, err)]
    async fn upstream_direct(&self, sni: &str, port: u16) -> Result<TcpStream, Error> {
        let target = self.resolver.lookup_socketaddr(sni, port).await?;

        let upstream_conn = happy_eyeballs::tokio::connect(target.addrs()).await?;

        Ok(upstream_conn)
    }
}

#[derive(Clone)]
struct SocksUpstreamConnector {
    socks_config: Arc<SocksConfig>,
}

impl SocksUpstreamConnector {
    fn config(&self) -> &SocksConfig {
        &self.socks_config
    }

    async fn new(socks: &Url) -> Result<Self, Error> {
        let socks_config = SocksUpstreamConnector::socks_config(socks).await?;

        Ok(Self {
            socks_config: Arc::new(socks_config),
        })
    }

    async fn socks_config(socks: &Url) -> Result<SocksConfig> {
        let dns_resolution = match socks.scheme() {
            "socks5" => SocksDnsResolution::Local,
            "socks5h" => SocksDnsResolution::Socks,
            _ => Err(anyhow!("Invalid scheme for socks"))?,
        };

        let socks_port = socks.port().unwrap_or(1080);
        let Some(socks_host) = socks.host_str() else {
            Err(anyhow!("Invalid socks url"))?
        };
        let lookup_result: LookupResult = lookup_host((socks_host, socks_port))
            .await?
            .collect::<Vec<_>>()
            .try_into()?;

        let socks_addr = lookup_result.with_port(socks_port);

        Ok(SocksConfig {
            dns_resolution,
            socks_addr,
        })
    }

    // maybe add retry logic for socks if first target addr fails
    #[instrument(skip_all, fields(target = ?target), err)]
    async fn connect(&self, target: TargetAddr) -> Result<TcpStream, Error> {
        // we could use happy eyeballs here this is not really common for
        // socks tho as far as I am aware for socks
        let upstream_conn = TcpStream::connect(self.socks_config.socks_addr.addrs()).await?;

        let mut upstream =
            Socks5Stream::use_stream(upstream_conn, None, FastSocksConfig::default()).await?;
        upstream.request(Socks5Command::TCPConnect, target).await?;

        Ok(upstream.get_socket())
    }
}

#[derive(Clone)]
enum DnsLookupMode {
    Ipv4,
    Ipv6,
    DualStack,
}

impl DnsLookupMode {
    fn includes_ipv4(&self) -> bool {
        match self {
            Self::Ipv4 => true,
            Self::Ipv6 => false,
            Self::DualStack => true,
        }
    }

    fn includes_ipv6(&self) -> bool {
        match self {
            Self::Ipv4 => false,
            Self::Ipv6 => true,
            Self::DualStack => true,
        }
    }
}

type CustomAsyncResolver = AsyncResolver<GenericConnector<RuntimeProviderWithSocks>>;

#[derive(Clone)]
struct UpstreamResolver {
    resolver: Option<Arc<CustomAsyncResolver>>,
    dns_lookup_mode: DnsLookupMode,
}

impl UpstreamResolver {
    async fn new(runtime_provider: RuntimeProviderWithSocks) -> Result<Self, Error> {
        let resolver = match &ARGS.dns {
            Some(dns) => Some(Self::create_resolver(dns, runtime_provider).await?),
            None => None,
        };

        let dns_lookup_mode = match (ARGS.ipv4, ARGS.ipv6) {
            (true, false) => DnsLookupMode::Ipv4,
            (false, true) => DnsLookupMode::Ipv6,
            (true, true) => DnsLookupMode::DualStack,
            (false, false) => Err(anyhow!("Atleast ipv4 or ipv6 have to be enabled"))?,
        };

        Ok(Self {
            resolver: resolver.map(Arc::new),
            dns_lookup_mode,
        })
    }
    async fn create_resolver(
        dns: &str,
        runtime_provider: RuntimeProviderWithSocks,
    ) -> Result<CustomAsyncResolver> {
        let dns_server = lookup_host(dns).await?.next();
        let Some(dns_server) = dns_server else {
            Err(anyhow!("No IP for DNS Server found"))?
        };
        let name_server_config = NameServerConfig::new(dns_server, Protocol::Tcp);

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(name_server_config);

        let connector = GenericConnector::new(runtime_provider);
        Ok(AsyncResolver::new(
            resolver_config,
            ResolverOpts::default(),
            connector,
        ))
    }

    #[instrument(skip_all, ret, err)]
    async fn lookup_socketaddr(&self, sni: &str, port: u16) -> Result<LookupResultWithPort, Error> {
        // If sni is already an ip we return early
        // this check is needed because ipv4_lookup does not support ip addresses
        // and will actually query the dns with ip addr
        if let Ok(ip) = sni.parse::<IpAddr>() {
            return Ok(LookupResult::Static(ip).with_port(port));
        }

        if let Some(resolver) = &self.resolver {
            let ips: LookupResult = match self.dns_lookup_mode {
                DnsLookupMode::Ipv4 => resolver.ipv4_lookup(sni).await?.try_into()?,
                DnsLookupMode::Ipv6 => resolver.ipv6_lookup(sni).await?.try_into()?,
                DnsLookupMode::DualStack => resolver.lookup_ip(sni).await?.try_into()?,
            };

            return Ok(ips.with_port(port));
        }

        // this method requires a port we ignore afterward
        let addr: LookupResult = lookup_host((sni, 80))
            .await?
            .filter(|addr| match addr {
                SocketAddr::V4(_) if self.dns_lookup_mode.includes_ipv4() => true,
                SocketAddr::V6(_) if self.dns_lookup_mode.includes_ipv6() => true,
                _ => false,
            })
            .collect::<Vec<_>>()
            .try_into()?;

        Ok(addr.with_port(port))
    }
}

#[derive(Clone)]
struct RuntimeProviderWithSocks {
    socks: Option<SocksUpstreamConnector>,
    inner: TokioRuntimeProvider,
}

impl RuntimeProviderWithSocks {
    fn new(socks: Option<SocksUpstreamConnector>) -> Self {
        Self {
            socks,
            inner: TokioRuntimeProvider::default(),
        }
    }
}

impl RuntimeProvider for RuntimeProviderWithSocks {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let Some(socks) = &self.socks else {
            return self.inner.connect_tcp(server_addr);
        };

        let sni = server_addr.ip().to_string();
        let is_excluded = &ARGS.socks_exclude.iter().find(|exclude| sni.eq(*exclude));
        if is_excluded.is_some() {
            info!("Excluded from socks");
            return self.inner.connect_tcp(server_addr);
        }

        let socks = socks.clone();
        Box::pin(async move {
            let target_addr = server_addr.to_target_addr()?;
            match socks.connect(target_addr).await {
                Ok(stream) => Ok(AsyncIoTokioAsStd(stream)),
                Err(err) => Err(std::io::Error::new(ErrorKind::Other, err)),
            }
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(ready(Err(std::io::Error::new(
            ErrorKind::Other,
            "UDP not supported",
        ))))
    }
}
