This package is based on the document [NAT Behavior Discovery Using STUN (RFC 5780)](https://www.netmanias.com/en/post/techdocs/6067/nat-network-protocol/nat-behavior-discovery-using-stun-rfc-5780).

## Types of NATs

NAT types in theory: {Address {dep/indep} & Port {dep/indep}} Mapping x {Address {dep/indep} & Port {dep/indep}} Filtering \
=> 2^4 = 16 types!

In 4 combinations of Address {dep/indep} & Port {dep/indep}, the "Addr indep & Port dep" is unlikely to be implemented \
=> 3^2 = 9 types in RFC 5780.

In 9 combinations of Binding & Filtering (RFC 5780), following 3 combinations are meaningless because their binding is narrower than filtering: \
- Addr dep Binding & no Filtering
- Addr-port dep Binding & no Filtering
- Addr-port dep Binding & Addr dep Filtering

=> 6 practical types of NATs to be considered:
1. Endpoint indep Binding & no Filtering, AKA. "Full cone" (RFC 4389)
2. Endpoint indep Binding & Addr dep Filtering, AKA. "Restricted cone" (RFC 4389)
3. Endpoint indep Binding & Addr-port dep Filtering, AKA. "Port-restricted cone" (RFC 4389)
4. Addr dep Binding & Addr dep Filtering, AKA. "Address symmetric"
5. Addr dep Binding & Addr-port dep Filtering, AKA. "Restricted address symmetric"
6. Addr-port dep Binding & Addr-port dep Filtering, AKA. "Strict symmetric" (RFC 4389)

## Candidate pairing by type of NAT

The tabulation for "classic STUN" (RFC 4389) has been done in pion/webrtc's wiki page [Candidate types and combinations of NAT types](https://github.com/pion/webrtc/wiki/Network-Address-Translation#candidate-types-and-combinations-of-nat-types)

