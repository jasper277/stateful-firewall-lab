# Stateful Packet Filtering & Network Security Report
**Author:** Ubong  
**Team:** Bincom Cyber Security Team  
**Date:** November 27, 2026  

---

## 1. Executive Summary & Lab Architecture
To validate host-level perimeter defenses without external hardware, an isolated dual-namespace virtual network was deployed on Linux using `iproute2` network namespaces (`ip netns`).

* **`ns-client` (`192.168.100.1/24`):** Simulates an external client/attacker node connected via `veth-client`.
* **`ns-server` (`192.168.100.2/24`):** Simulates a hardened enterprise application server connected via `veth-server`, protected by a stateful `iptables` firewall.

```text
+-----------------------+                +-----------------------+

|       ns-client       |                |       ns-server       |
|   IP: 192.168.100.1   |                |   IP: 192.168.100.2   |
|     [veth-client] <---+--- veth pair --+---> [veth-server]     |
+-----------------------+                |  (iptables Stateful)  |
                                         +-----------------------+
```

---

## 2. Stateful Firewall Rule Design (`iptables`)
The firewall inside `ns-server` enforces a **Default-Deny** posture:

1. **Default Drop Policy (`-P INPUT DROP`, `-P FORWARD DROP`):** Drops all unsolicited inbound and routed packets unless explicitly matched by an `ACCEPT` rule.
2. **Loopback Isolation (`-A INPUT -i lo -j ACCEPT`):** Permits internal inter-process communication on the loopback interface.
3. **Invalid State Dropping (`-m conntrack --ctstate INVALID -j DROP`):** Drops malformed packets or out-of-sequence TCP flags before state evaluation.
4. **Stateful Inspection (`-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`):** Consults the kernel's `nf_conntrack` state table to allow return traffic for legitimate sessions without opening static high-numbered ephemeral ports.
5. **Anti-Spoofing Mitigation:** Drops packets entering `veth-server` claiming source addresses from reserved loopback (`127.0.0.0/8`) or non-lab RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`).
6. **Strict Service Allowlisting:** Accepts `NEW` TCP connections exclusively on ports `443` and `8443`.

---

## 3. Firewall & Connection Tracking Verification
* **ICMP Echo Block:** After applying the ruleset, `ping` from `192.168.100.1` to `192.168.100.2` resulted in `100% packet loss`, confirming unapproved protocols are silently dropped.
* **Unauthorized Port Block:** Connection attempts to TCP port `8080` timed out, while TCP port `8443` completed the 3-way handshake and registered in the connection tracking table.

### Verification & Ruleset Transcript
```text
=== 1. VERIFYING PING IS BLOCKED AFTER FIREWALL ===
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.

--- 192.168.100.2 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1051ms

[Blocked as expected]

=== 2. VERIFYING PORT 8080 IS BLOCKED ===
[Port 8080 dropped as expected]

=== 3. EXPORTING IPTABLES RULES ===
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 127.0.0.0/8 -i veth-server -j DROP
-A INPUT -s 10.0.0.0/8 -i veth-server -j DROP
-A INPUT -s 172.16.0.0/12 -i veth-server -j DROP
-A INPUT -i veth-server -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -i veth-server -p tcp -m tcp --dport 8443 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTABLES-DROP: "
```

### Kernel Connection Tracking State (`/proc/net/nf_conntrack`)
```text

```

---

## 4. Plaintext Sniffing vs. Encrypted Transport Analysis

### Plaintext Interception (`plaintext.pcap`)
When transmitting data over an unencrypted TCP socket on port `8443`, `tcpdump` captured the entire TCP payload in cleartext, exposing sensitive strings (`ADMIN_CREDENTIALS=BincomSec2026!`) to any observer on the wire.

```text

```

### Cryptographic Mitigation (`encrypted.pcap`)
Wrapping the session in TLS (`openssl s_server` / `s_client`) negotiated an encrypted symmetric tunnel after the TLS handshake. Inspecting `encrypted.pcap` confirmed that payload bytes were completely obfuscated as high-entropy ciphertext, mitigating passive reconnaissance sniffing.

```text
08:13:56.683654 IP 192.168.100.1.44770 > 192.168.100.2.8443: Flags [S], seq 2057352952, win 64240, options [mss 1460,sackOK,TS val 1908801378 ecr 0,nop,wscale 10], length 0
E..<.r@.@.....d...d... .z...........I..........
q..b.......

08:13:56.683714 IP 192.168.100.2.8443 > 192.168.100.1.44770: Flags [S.], seq 2621503341, ack 2057352953, win 65160, options [mss 1460,sackOK,TS val 1304388542 ecr 1908801378,nop,wscale 10], length 0
E..<..@.@..g..d...d. ....@.mz.......I..........
M.c.q..b...

08:13:56.683745 IP 192.168.100.1.44770 > 192.168.100.2.8443: Flags [.], ack 1, win 63, options [nop,nop,TS val 1908801378 ecr 1304388542], length 0
E..4.s@.@.....d...d... .z....@.n...?I{.....
q..bM.c.
08:13:56.686842 IP 192.168.100.1.44770 > 192.168.100.2.8443: Flags [P.], seq 1:1534, ack 1, win 63, options [nop,nop,TS val 1908801381 ecr 1304388542], length 1533
E..1.t@.@.....d...d... .z....@.n...?Ox.....
q..eM.c............s..E.<.......D....3.
..J,.4DM... vE......".l.0_.].......FA+...2...<.......,.0.........+./...$.(.k.#.'.g.
...9.	...3.....=.<.5./...o..............
.....................#.............6.4	.	.	..................	.
...........................+........-.....3..........q.:....T..B.x]b..c..;...*wu.@.y).jE|8..m.6^..)L.%....j#.....A.{`	v._....:.#...c`f..{....<.^p....0....2E..<W.3.EX4S6X.z...]......._X...b....G.f.C.S.....K.v..l........b^Yg..A.j.V.A.(...z^..\.....{.BW.y/...a.D.[..6;X}N..di.N.GNA.....T...^......... ..F....e.`g%v?e.	....S..Rd.R...S,....m.a............5...@.X...P.Z.I0..@m..lP&...9.M.........<c.$..<..I...`.T;J..q	k.M2;..:.A..x...9.e...N..h%.v2S..T...^e2.Q.y`.....#..O..$|...e...?.W21c.Cf......i.K.x..b..g....F9ABjh-c .8..g..*rM9..XDO...B.:.:............%.P..`..
...tP.a...:'.w..T...}[.j......0`/h,...&....Y .D	r..U.5.Q'>.]'........r..Q.n.x......X....u[.......Y..|}...?!....zj.\.`&...wE.LdxZ.pxF.;.i....`..r.Q.0..Z.tr..W.Ho.,...m.p).B........WW9...eX.kG..:...p.....<q.`N.X.F.Sz......vzT.1....e-.".~.ub...<X..c..O..e..L.D.]`I..5..]V.d....RCT.nT... ..E..Fm<h...L\<.q[z..r.9 .{......%..<..etf.v
....ic......R....a.....P.....e..s._3...G{)k.\...kT.....m..ec........GX/[.........D.........&T... h....z'fc.Ua[(..b1..G6z9..C..^..t.:	.U...25..{{..[x..3....4....=.....].'..h".o^.O)...9.....%'......x.:....+...G5.0U....VyRv.9d.8:.wiQ.8-..9.6` .>...u<.T]E..v.->.......B.g..r=<./....C..cC.x.....v....,e.-L.sb..u.N.
...)...........Oa..`.W.G..%b`.	U..#b......9.....Li._...T..(....'.jK... e?..D5s$eeR..RR..V..T....^.yS.c..........
08:13:56.686888 IP 192.168.100.2.8443 > 192.168.100.1.44770: Flags [.], ack 1534, win 66, options [nop,nop,TS val 1304388545 ecr 1908801381], length 0
E..4..@.@.B...d...d. ....@.nz......BI{.....
M.c.q..e
```
