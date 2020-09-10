This package is based on the document [NAT Behavior Discovery Using STUN (RFC 5780)](https://www.netmanias.com/en/post/techdocs/6067/nat-network-protocol/nat-behavior-discovery-using-stun-rfc-5780).

Tools:
- nat-discoverer.go: Go program, forked from [pion/stun/cmd/stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour), updated to support both "classic STUN" (RFC 4389) & STUN (RFC 5780)
- nat-discovery.py: Python script, forked from [automation-stack/nat-discovery](https://github.com/automation-stack/nat-discovery), fixed bugs and updated to support both "classic STUN" (RFC 4389) & STUN (RFC 5780)
- check-server/: A STUN client using client-socket and send basic Mapping Request (without attribute) to inspect server's response
    - public-STUN-servers\*.txt: Lists of hundreds of public servers


## Types of NATs

NAT types in theory: {Address {dep/indep} & Port {dep/indep}} Mapping x {Address {dep/indep} & Port {dep/indep}} Filtering \
=> 2^4 = 16 types!

In 4 combinations of Address {dep/indep} & Port {dep/indep}, the "Addr indep & Port dep" is unlikely to be implemented \
=> 3^2 = 9 types in RFC 5780.

In 9 combinations of Binding & Filtering (RFC 5780), following 3 combinations are meaningless because their binding is narrower than filtering:
- Addr dep Binding & no Filtering
- Addr-port dep Binding & no Filtering
- Addr-port dep Binding & Addr dep Filtering

=> 6 practical types of NATs to be considered:
1. Endpoint indep Binding & no Filtering, AKA. "Full cone" (RFC 4389)
2. Endpoint indep Binding & Addr dep Filtering, AKA. "Restricted cone" (RFC 4389)
3. Endpoint indep Binding & Addr-port dep Filtering, AKA. "Port-restricted cone" (RFC 4389)
4. Addr dep Binding & Addr dep Filtering, AKA. "Address symmetric"
5. Addr dep Binding & Addr-port dep Filtering, AKA. "Restricted address symmetric"
6. Addr-port dep Binding & Addr-port dep Filtering, AKA. "Strictly symmetric" (RFC 4389)

## Candidate pairing by NAT type

The tabulating for "classic STUN" (RFC 4389) has been done in pion/webrtc's wiki page [Candidate types and combinations of NAT types](https://github.com/pion/webrtc/wiki/Network-Address-Translation#candidate-types-and-combinations-of-nat-types)

Because
- \[R\_cone\] A peer after **cone NAT** can use its server reflexive candidate derived from **STUN**;
- \[R\_sym\] A peer after **symmetric NAT** must use its peer reflexive candidate derived from its **peer**;

We have following pairing rules:
- \[R\_cone-cone\] When both peers are after cone NAT, they can both use their server reflexive candidates;
- \[R\_sym-sym\] When both peers are after symmetric NAT, they must use **relay** candidates derived from *TURN*;
- \[R\_cone-sym\] When one peer is after cone NAT while the other is after symmetric NAT, server reflexive candidate can be used in combination with peer reflexive candidate to establish peer connection if the filter is not too strict, or else _relay candidates must be used for **port-restricted cone**_.

Thus, we have the following the table for our 6 practical NAT types:

|    \    | F.Cone     | R.Cone     | _PR.Cone_  | A.Sym      | RA.Sym     | S.Sym      |
|:-------:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| F.Cone  |srflx       |srflx       |srflx       |srflx\prflx |srflx\prflx |srflx\prflx |
| R.Cone  |srflx       |srflx       |srflx       |srflx\prflx |srflx\prflx |srflx\prflx |
|_PR.Cone_|srflx       |srflx       |srflx       |**relay**   |**relay**   |**relay**   |
| A.Sym   |prflx\srflx |prflx\srflx |**relay**   |relay       |relay       |relay       |
| RA.Sym  |prflx\srflx |prflx\srflx |**relay**   |relay       |relay       |relay       |
| S.Sym   |prflx\srflx |prflx\srflx |**relay**   |relay       |relay       |relay       |

Where NAT types
* F.Cone: Full-cone NAT
* R.Cone: Restricted-cone NAT
* PR.Cone: Port restricted-cone NAT
* A.Sym: Address symmetric NAT
* RA.Sym: Restricted address symmetric NAT
* S.Sym: Strictly symmetric NAT

and candidate types
* srflx: Server reflexive candidate (derived from STUN)
* prflx: Peer reflexive candidate (derived from the other peer)
* relay: Relay candiate (derived from TURN)
* (one candidate type): both peers use this type of candidate, eg. both "srflx", both "relay"
* (candR\candC): cand{R,C} is the candidate for the peer on this {row, column}
