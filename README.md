# 🌊 CubeDns

A small DNS Resolver in C#.

## Usage

```bash
cubedns [options] {Hostname} [arguments]

Options:

    --os-resolver {Hostname}
        Resolve a hostname or an IP address using System.Net.Dns.

    --cube-resolver {Hostname} [DNS Server] [QTYPE] [QueryTransport]
        My DNS Resolver implementation.

    --doh-json {Hostname} [DNS Server] [QTYPE] [DNSSEC]
        An implementation of Cloudflare DoH Json format.

Arguments:

    [DNS SErver]: For UDP, TCP, and DoT queries, an DNS server IP address in plain string. For DoH queries, an query URI. For example, https://dns.google/dns-query

    [QTYPE]: DNS query type.

    [QueryTransport]:

        Udp
            DNS wireformat via UDP.
        Tcp
            DNS wireformat via TCP.
        DoT
            DNS over TLS (RFC 7858).
        DoH
            DNS over HTTPS (RFC 8484).
    
    [DNSSEC]: DO bit - DNSSEC data (either boolean or numeric value).

Examples:

    cubedns --os-resolver google.com
    cubedns --cube-resolver google.com
    cubedns --cube-resolver google.com 1.1.1.1
    cubedns --cube-resolver google.com 1.1.1.1 AAAA
    cubedns --cube-resolver google.com 1.1.1.1 AAAA DoT
    cubedns --cube-resolver google.com https://cloudflare-dns.com/dns-query AAAA DoH
    cubedns --doh-json google.com 
    cubedns --doh-json google.com https://cloudflare-dns.com/dns-query
    cubedns --doh-json google.com https://cloudflare-dns.com/dns-query AAAA
    cubedns --doh-json google.com https://cloudflare-dns.com/dns-query AAAA true
```

## Goals

- [x] DoH Opportunistic Privacy Profile
- [x] Cloudflare DoH Json Format

## RFCs implemented

- [x] [RFC 1034](https://tools.ietf.org/html/rfc1034): Base DNS concepts.
- [x] [RFC 1035](https://tools.ietf.org/html/rfc1035): Base DNS specification.
- [ ] [RFC 2782](https://tools.ietf.org/html/rfc2782): DNS SRV Service Location.
- [x] [RFC 3596](https://tools.ietf.org/html/rfc3596): DNS IPv6 extension.
- [x] [RFC 7858](https://tools.ietf.org/html/rfc7858): DNS over TLS specification.
- [x] [RFC 8484](https://tools.ietf.org/html/rfc8484): DNS over HTTPS specification.

## License

Licensed under [GPLv3](LICENSE).

© 2020 database64128
