arpcap
======

Captures ARP packets without putting the interface in promiscious mode (needs to run as root).
Only tested on GNU/Linux so far.

run `make` to build.

Example :

<pre>
./arpcap eth0
ARP opcode=REPLY size=60 sender_mac=70:5a:b6:e0:5f:34 sender_ip=192.168.17.2 target_mac=9c:b6:d0:e1:b2:3 target_ip=192.168.17.35
ARP opcode=REQUEST size=60 sender_mac=f4:c4:d6:1:17:dd sender_ip=192.168.17.32 target_mac=00:0:0:0:0:0 target_ip=192.168.17.32
ARP opcode=REQUEST size=60 sender_mac=f4:c4:d6:1:17:dd sender_ip=192.168.17.32 target_mac=00:0:0:0:0:0 target_ip=192.168.17.32
ARP opcode=REQUEST size=60 sender_mac=f4:c4:d6:1:17:dd sender_ip=192.168.17.32 target_mac=00:0:0:0:0:0 target_ip=192.168.17.32
ARP opcode=REPLY size=60 sender_mac=70:5a:b6:e0:5f:34 sender_ip=192.168.17.2 target_mac=9c:b6:d0:e1:b2:3 target_ip=192.168.17.35
ARP opcode=REQUEST size=60 sender_mac=f4:c4:d6:1:17:dd sender_ip=192.168.17.32 target_mac=00:0:0:0:0:0 target_ip=192.168.17.32
ARP opcode=REQUEST size=42 sender_mac=80:d2:1d:30:8:f sender_ip=192.168.17.20 target_mac=00:0:0:0:0:0 target_ip=192.168.17.37
</pre>

