# sniproxy

This tool can be used to proxy requests based on the SNI (Server Name Indication) TLS extension or the HTTP Host. 
It is a very basic transparent tls proxy based on tokio.

My personal usecase is to redirect a specific domain via dns to this proxy and then redirect it over a vpn provider.

The proxy supports direct connections and connections via socks5 proxies