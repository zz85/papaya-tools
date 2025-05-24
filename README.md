# papaya-tools 🔨🦀🐝🍍
Experimental collection of eBPF / aya / network / system / tracing utilities

### Tools

| Tool Name    | Description                           |
|--------------|---------------------------------------|
| [profile-bee](https://github.com/zz85/profile-bee/)  | CPU profiling                         |
| [tcc-trace](https://github.com/zz85/tcc-trace)    | Peek at congestion control changes    |
| [snisnoop](snisnoop)     | Find processes and domains for outgoing TLS handshakes             |
| [quicsnoop](quicsnoop)     | Find SNI of initial QUIC packets                 |
| [ipipsnoop](ipipsnoop)   | Monitor IP-in-IP encapsulation traffic (uses XDP)            |
| [ipswap](ipswap)         | Modify source IP addresses of selective outgoing packets (uses tcbpf-egress) |
| [spawnsnoop](spawnsnoop) | Find out processes that launch and terminates, using tracepoints |

#### snisnoop - short for TLS SNI (Server Name Indication) Snoop.

```bash
Example:
$ sudo snisnoop --interface eth0

TIME         PID      SOURCE                 DESTINATION            SNI
----------------------------------------------------------------------------------------------
10:03:50     8548     172.19.192.80:42464    74.6.143.25:443        yahoo.com
10:03:56     8737     172.19.192.80:34792    172.217.14.206:443     google.com
10:04:08     9049     172.19.192.80:60278    3.163.24.19:443        aws.com
```

Finds out what outgoing TLS connections host is making.
Uses TC-BPF classifier.

Similar ideas to my implementation of JA4dump (like tcpdump but generates JA4 signatures),
although that implementation uses mostly user-space implementation.
https://github.com/zz85/packet_radar/blob/master/src/bin/ja4dump.rs


#### tcc trace (traffic congestion control trace)

```bash
$ sudo target/release/tcc-trace --port 443

Filtering port: 443
TCP Probe attached via BPF Tracepoint in 1.452ms
Waiting for Ctrl-C...
1.72180s | 0.000 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 65535 srtt 16980 rcv_wnd 62592 length 0
1.73081s | 9.009 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 62592 length 2416
1.73084s | 9.042 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 60288 length 2416
```

Uses Tracepoint to find congestion control parameters set by the OS

#### Ideas cooking..
- connection drop catcher - find out connections are dropping because process are too busy
- tracepoint-snisnoop - but implmennted with tracepoint
- implement sni parser in ebpf rather than user space
- publish this as a crate
- explore raw tracepoints and btf raw tracepoints
- generic k/uprobe tracker
- monitoring process state transitions

#### Links
- https://github.com/iovisor/bcc/
- https://github.com/aya-rs/awesome-aya

