# papaya-tools
Experimental collection of eBPF / aya utilities

### Tools

#### snisnoop - short for TLS SNI (Server Name Indication) Snoop.
Finds out what outgoing TLS connections host is making.
Uses TC-BPF classifier.

Similar ideas to my implementation of JA4dump (like tcpdump but generates JA4 signatures),
although that implementation uses mostly user-space implementation.
https://github.com/zz85/packet_radar/blob/master/src/bin/ja4dump.rs


#### tcc trace (traffic congestion control trace)
Uses Tracepoint to find congestion control parameters set by the OS
See https://github.com/zz85/tcc-trace
