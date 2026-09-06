`bcfwd` forwards directed UDP broadcast packets to all other attached networks
(i.e. other than the one on which they were received), changing the destination
address to the corresponding directed broadcast address.  Requires `CAP_NET_RAW`
to open a raw UDP socket.

It's intended to be used as a tiny container image on a router with multiple
VLANs, to allow discovery protocols to cross VLAN boundaries.  The daemon
forwards everything on every interface, so the host should use firewall rules to
limit what goes in and out.
