use anyhow::Result;
use fast_socks5::util::target_addr::{TargetAddr, ToTargetAddr};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use tokio::net::ToSocketAddrs;
use trust_dns_resolver::lookup::{Ipv4Lookup, Ipv6Lookup};
use trust_dns_resolver::lookup_ip::LookupIp;

// todo: test this
// should be quite easy
#[derive(Debug)]
pub(crate) enum LookupResult {
    Ipv4(Ipv4Lookup),
    Ipv6(Ipv6Lookup),
    DualStack(LookupIp),
    Static(IpAddr),
    Tokio(Vec<SocketAddr>),
}

impl TryFrom<Vec<SocketAddr>> for LookupResult {
    type Error = EmptyLookupResultError;

    fn try_from(value: Vec<SocketAddr>) -> Result<Self, Self::Error> {
        if value.len() == 0 {
            return Err(EmptyLookupResultError {});
        };
        Ok(Self::Tokio(value))
    }
}

impl TryFrom<Ipv4Lookup> for LookupResult {
    type Error = EmptyLookupResultError;

    fn try_from(value: Ipv4Lookup) -> Result<Self, Self::Error> {
        if value.iter().next().is_none() {
            return Err(EmptyLookupResultError {});
        }
        Ok(Self::Ipv4(value))
    }
}

impl TryFrom<Ipv6Lookup> for LookupResult {
    type Error = EmptyLookupResultError;

    fn try_from(value: Ipv6Lookup) -> Result<Self, Self::Error> {
        if value.iter().next().is_none() {
            return Err(EmptyLookupResultError {});
        }
        Ok(Self::Ipv6(value))
    }
}

impl TryFrom<LookupIp> for LookupResult {
    type Error = EmptyLookupResultError;

    fn try_from(value: LookupIp) -> Result<Self, Self::Error> {
        if value.iter().next().is_none() {
            return Err(EmptyLookupResultError {});
        }
        Ok(Self::DualStack(value))
    }
}

impl LookupResult {
    pub(crate) fn with_port(self, port: u16) -> LookupResultWithPort {
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
pub(crate) struct EmptyLookupResultError {}

impl Display for EmptyLookupResultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Empty lookup result")
    }
}

impl std::error::Error for EmptyLookupResultError {}

#[derive(Debug)]
pub struct LookupResultWithPort {
    socket_addrs: Vec<SocketAddr>,
}

impl LookupResultWithPort {
    pub(crate) fn addrs(&self) -> impl ToSocketAddrs + '_ {
        &self.socket_addrs[..]
    }
}

impl ToTargetAddr for LookupResultWithPort {
    // vec is never empty so we can just index directly
    fn to_target_addr(&self) -> std::io::Result<TargetAddr> {
        Ok(TargetAddr::Ip(self.socket_addrs[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use tokio::net::lookup_host;
    use trust_dns_resolver::lookup::Lookup;
    use trust_dns_resolver::proto::op::Query;
    use trust_dns_resolver::proto::rr::RData;

    fn empty_lookup<T: From<Lookup>>() -> T {
        return Lookup::new_with_max_ttl(Query::new(), Arc::new([])).into();
    }

    fn lookup_result_factory<T>(rdata: RData) -> Result<LookupResult>
    where
        T: TryInto<LookupResult> + From<Lookup>,
        T::Error: Into<Error>,
    {
        let lookup: T = Lookup::from_rdata(Query::new(), rdata).into();
        let result = lookup.try_into().map_err(Into::into)?;
        Ok(result)
    }

    async fn socket_addr<T: ToSocketAddrs>(input: T) -> Result<Vec<SocketAddr>> {
        Ok(lookup_host(input).await?.collect())
    }

    #[tokio::test]
    async fn ipv4_should_work() -> Result<()> {
        let rdata = RData::A(Ipv4Addr::LOCALHOST.into());
        let lookup_result = lookup_result_factory::<Ipv4Lookup>(rdata)?.with_port(80);
        let addrs = socket_addr(lookup_result.addrs()).await?;

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], (Ipv4Addr::LOCALHOST, 80).into());

        Ok(())
    }

    #[test]
    fn empty_ipv4_should_error() {
        let result = LookupResult::try_from(empty_lookup::<Ipv4Lookup>());

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ipv6_should_work() -> Result<()> {
        let rdata = RData::AAAA(Ipv6Addr::LOCALHOST.into());
        let lookup_result = lookup_result_factory::<Ipv6Lookup>(rdata)?.with_port(80);
        let addrs = socket_addr(lookup_result.addrs()).await?;

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], (Ipv6Addr::LOCALHOST, 80).into());

        Ok(())
    }

    #[test]
    fn empty_ipv6_should_error() {
        let result = LookupResult::try_from(empty_lookup::<Ipv6Lookup>());

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dualstack_should_work() -> Result<()> {
        let rdata = RData::A(Ipv4Addr::LOCALHOST.into());
        let lookup_result = lookup_result_factory::<LookupIp>(rdata)?.with_port(80);
        let addrs = socket_addr(lookup_result.addrs()).await?;

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], (Ipv4Addr::LOCALHOST, 80).into());

        Ok(())
    }
}
