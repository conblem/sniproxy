# Docker compose setup for sniproxy with tailscale 
## Still WIP

![Docker compose setup](./Docker%20Compose%20setup.drawio.svg)

This is an example setup for sniproxy with tailscale.
It is used to conditionally route the traffic for a specific domain through a vpn

## Steps to get this running for yourself
- [ ] Change all references of '100.78.78.114' to your tailscale ip 
- [ ] Fix up the wg0.conf with your VPN providers config
- [ ] Create a .env file with the contents of .env.example
- [ ] Add the Tempo API key and username to the .env file
- [ ] Change the dns server of the sniproxy to your dns server of choice (I use the one provided by the vpn provider)