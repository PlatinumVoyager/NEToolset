# NEToolset
Network Engineer Toolset is an "in-development" collection of networking tools and utilities that solidify and accentuate the process of deploying network based tooling across areas relative to the domain of network operations/engineering.

## Source Files:
`fcurl.c`- SOCKS5 proxy "mask" detection via TORSOCKS proxy.

Socks5 proxy points to:
```C
#define TORSOCKS5_HOST_PROXY "127.0.0.1:9050"
```

The FQDN (Fully Qualified Domain Name) target points to:
```C
#define SOCKS5_PROXY_FQDN "https://www.ifconfig.me"
```

![sub2dec_img](https://github.com/PlatinumVoyager/NEToolset/blob/main/sub2dec.png)

`sub2dec.go` - A basic tool used for calculating nodes available within a subnet via classful/classless target prefix notation (Ex: /24, /13, etc)

`detectpacket.go` - A source tool for obtaining IPv4 packet header information that can be used to display target indicators (via setHost = true) or NHS (Null Host Source: identifies as a target not being set)

Subsequent information displayed to the terminal shows all packets that have been copied over to the primary network interface for filtering. Targets that appear are ALL layer layer 3 (Network) packets where the TCP/IPv4 source or destination address is set to your link-local address and copied from the source NIC defined by "device string" within `detectpacket.go` thus allowing the packet function format string to display them in a later stage of execution within `detectpacket.go`.
* `detectpacket.go` captures ALL layer 3 (Network) traffic that contains your link-local address within the packet header sent to NIC.
* Display's NHS (Null Host Source) as well as THA (Target Host Acquisition) packet function format strings.
