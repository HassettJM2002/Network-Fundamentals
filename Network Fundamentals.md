# CCTC Networking
##### Home for the Section https://net.cybbh.io/public/networking/latest/index.html
##### Day 1 Repos: https://net.cybbh.io/public/networking/latest/lesson-1-fundamentals/fg.html
## Day 1 - Network Fundamentaks
<details>
    ssh student@10.50.37.90 -X
	tmerminator
#### JOHA-M-005

#### Basics
#####
    
    bits -> 0 / 1, on or off
    byte -> 8 bits -> 0 -> 255

#### Base n formats
    Base 2 (Binary) -> 0 - 1 
    Base 10 (Decimal) -> 0 - 9
    Base 16 (Hexidecimal) -> 0 - F  

### OSI Model Brief Overview
<details>
    
    7 -> Application
        Use Transport Layer, build off of Transport Layer
    6 -> Presenetation
        Use Transport Layer, build off of Transport Layer
    5 -> Session:
        Use Transport Layer, build off of Transport Layer
    4 -> Transport:
        Handling Data, TCP handshake, UDP 
    3 -> Network:
        Tying networks together
    2 -> Data Link: 
        Modem, physical to logical, arp and vlan info such as trunking, how info gets from one device to another
    1 -> Physical
</details>
### Important Standards
    Organizations such as IANA, IETF, IEEE, set standards that should be used universally
    RFCs give write ups on the standards, to look at the source, look at the RFC

### OSI Indepth Overview
#### Layer 1: Physical Layer
    Hardwork layer, Encoding, Data transmisision and Physical Network Design
#### Layer 2: Data Link (Has 2 Layers)
##### 1) MAC (Meda Access Control)
    MAC Address
##### 2) LLC (Logical Link Control)
    Manages communications between devices
##### Ethernet Header
    Dest MAC | Source MAC | Ethertype
    6 Bytes  | 6 Bytes    | 2 Bytes
                            Ether Types:
                                0x0800 IPv4
                                0x0806 ARP
                                0x86DD IPv6
                                0x8100 Vlan Tag
    VLAN: Creates a virtual LAN using the ethernet header

    On a local network, all that is required is an ARP Header to route packets 
    
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/74ece6fd-ceda-48b6-8fe7-9df4dffca261)
    Byte offset, use the Offset Size, then add the 0 1 2 3

#### Layer 3: Network
##### IPv4
    Most common protocols are
        IPv4
        IPv6
    Headers for IPv4
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/f6790ed4-db2f-48c9-a1f3-71a8afc75fd3)

    Bit Shift, depends on where you start in the bit, 1 will not always be 1
    - Fragmentation: If there packets are too big, it will fragment
        The first will have an offset of 0 with more fragement turned on
        the last one will have an offset of X with more fragment turned off
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/7aaa29dd-ed90-438e-ae5a-5cb7a569409b)
##### IPv6
    Used to address the problem of running out of ip addresses
    Used to secure it more, will stop packet injection
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/b747840a-dfac-45ec-a47d-a1d17cea2821)
##### IPv4 vs IPv6
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/73f9500a-1066-4d79-9c87-358839740270)

###### Fingerprinting
    Different Vendors have different TTLs which can be used to tell what OS is being used
        Linux                     64
        Google's Cust Linux       64
        FreeBSD                   64
        Windows XP                128
        Win 7                     128
        Cisco Router              255

##### ICMP
    Pings are only two types of icmp ping    
##### **Zero Config**
    Plug in device and allow to communicte with it
        IPv4
            APIPA, RFC 3927
        IPv6
            SLAAC, RFC 4862


#### Layer 4: Transport
##### TCP
    Reliable, three way handshake, expected to be connected to certain ports which refer to applications
    SYN -> SYN/ACK -> ACK
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/678dff3b-d767-40ee-a9c3-29d56c25d3fa)
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/360de4e0-ceb6-421c-8407-51dca75a0442)
#####
    Active -> the recviever is sending packets
    Passive -> Not getting any packets back
##### UDP
        No three way handshake, doesn't care if some things are lost
        Designed to get information to the otherside very quickly
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/eb0ed1fe-4ed3-44eb-9062-bc8e8520ed45)

#### Layer 5: Session
    SOCKs, itneract with the middle man, aka a proxy
    NetVIOS
    PPTP/L2TP
    RPC
##### SOCKS 4/5 (TCP 1080)
##### PPTP (TCP 1723)
##### L2TP (TCP 1701)
    Tunneling, encapsulates it in another protocol
##### SMB/CIFS (TCP 139/445 and UDP 137/138)
    Share Data
##### RPC (Any Port)
    RPC is a request response prootocol to get information on the network

#### Layer 6: Presentation
    Responsilbe for tranlating and formating data
    as well as Encoding, Encryption, and Compression
    - Symmetric Encryption
        Both have the same code
    - Assymetric Encryption
        Different info, tied back and used to decrypt
#### Layer 7: Application
    
##### FTP (TCP 20/21)
    - FTP : file transfer protocol used to transfer files, client server premise
    - Servers are sockets
###### FTP Active
    Server is sending packet to user via port 20
###### FTP Passive
    FTP server waits, will send packet to port that opened by server, access port and will respond with data, its like a double request

#### SSH (TCP 22)
    Assymetric PKI for key exchange
    Symmetric for session
    User authentication
    Data Stream channeling

    SSH <username>@<ip address>
    
    1) Sends TCP connetion to IP after 3 way handshake
    2) Then must authenticate with username and password, will try to login as the current user if none is specified
    3) Key Exchange, will store key in ssh hosts, will store it to keep secure

    - Not limited to one data stream
##### SSH Arhictecure
    Server
    Client
    Session
    Keys
        User Key 
        Host Key
        Session Key
    Key Generator
#### Telnet (TCP 23)
    PLain Text
#### SMTP (TCP 25)
#### TACAS (TCP 49)
    Transfer user name passwords and configartions
#### HTTP/s (TCP 80/443)
    Get web request to get reqeuest
#### Other COmmon Application Layer Protocols 
    POP (TCP 110)
    IMAP (TCP 143)
    RDP (TCP 3389)
    DNS (Query/Response TCP/UDP 53)
    DHCP (UDP 67/68)
    TFTP (UDP 69)
    NTP (UDP 123)
    SNMP (UDP 161/162)

### Other Networking Stuff
##### Network Traffic Sniffing
    Being able to capture packets on the network
##### Capture Library
    Libpcacp, WinPcap, NPCAP make traffic captures possible
    Wireshark can also be used
    Libpcap is installed on most flavours of linux

    How it works
    NIC -> wifi adapter, pulling data off wireless, data is sent to kernel, if its not to you, it would usually drop it, 
    but in promiscus mode, it will accept everything
    Normally it will remove through layers, but in prosicus mode, will forward as is, raw, sends it to current user space
#### Wireshark, TCPDUMP, and DPFS
##### Wireshark
    Protocol Hieracrchy
        Shows protocols and layers of the osi model
    Conversations / Endpoints
        Shows conversations 
            or
        the the endpoints of the conversations
    Pref:
        Prot -> TCP -> Relative Seq #

    Wireshark is not very efficient
##### TCPDUMP
###### to find where tcpdump is located
    which tcpdump
###### Example of how to use tcpdump
    Read from interface
        sudo tcpdump -i ens3 not port22
    Verbose read
        sudo tcpdump -i ens3 not port 22 -vv
    Read data
        sudo tcpdump -i ens3 not port 22 -nvv
    tcpdump -D
        Lists all availbe itnerfaces to capture on
##### TCP dump if not set it will set it to default
    Write to pcap file: tcpdump -w <>.pcap
    To read the file: tcpdump -r <>.pcap
#### Can use all the commands used in BASH
    grep, wc -l, etc
#### Berkely Packet FIlters (BPF)
    tcpdump {A} [B:C] {D} {E} {F} {G}

    A = Protocol (ether | arp | ip | ip6 | icmp | tcp | udp)
    B = Header Byte offset
    C = optional: Byte Length. Can be 1, 2 or 4 (default 1)
    D = optional: Bitwise mask (&)
    E = Operator (= | == | > | < | <= | >= | != | () | << | >>)
    F = Result of Expresion
    G = optional: Logical Operator (&& ||) to bridge expressions

    Example: --> find packets with IPv4, looks for packets without dest port 22 and 23
    tcpdump 'ether[12:2] = 0x0800 && (tcp[2:2] != 22 && tcp[2:2] != 23)'

    tcpdump -r something.pcacp 'tcp[13] = 0x10' -> only ones with that set : most exclusive
    tcpdump -r something.pccap 'tcp[13] & 0x10 = 0x10' -> will only look at that bit : most inclusive

    tcpdump -r something.pcap 'i[1] & 0xFC = 4'
##### Cheat sheet for BPF -> https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693 
##### Layer 2 Switching Technologies / switch Operation
    Fast Forward -> only looks at dest mac
    frag free -> first 64 bytes
    store and fwd -> entire frame and fcs
###### Cam Table
    stores information of MAC addresses on available ports
    Not vlans, broadcast to everything
    With vlan, will only broadcast it to ports with associated vlan tag
###### IEEE 802.1AD "Q and Q"
    Double tag, can send stuff to one vlan and another vlan
###### STP (Spanning Tree Protocol)
    Dynamic way to open and close links as we need them
    Root Bridge -> who has access to the router, least amount of hops
    Once elected does this process
    2. Identify the Root ports on non-root bridge
    3. Identify the Designated port for each segment
    4. Set alternate ports to blocking state
###### Layer 2 Dis Cover Protocol
1. Way for switches to talk to eachother
   - CIsco Disc Prot
     - Foundary Dic Prot
        Link Layer Disc Prot
###### VTP (VLAN Trunking Protocol)
    VTP server with the revision takes over the domain and puts out vtp information
###### Port Security
    Modes
        Shutdown -> shut off
        Restrict -> restrict to port
        Protect -> allow but log
    We can assign mac address to a port
    If port security is broken
        will do either one of the three options
##### Layer 3 Routing Technologies
###### Routing
    routing tables have networks associating to ports
        network address and CIDR
        X.X.X.X / Y
 ![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/63a3c26f-3b19-45dd-a501-c948533fe481)
##### Lookup Proc
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/2a2bdf28-3d35-4b1c-9215-310994a1f15d)
##### Routed vs Routing
1. IP prefix filtering
2. BGP hijacking detection
    - Tracking the change in TTL of incoming packets
    - Increased Round Trip Time (RTT) which increases latency
    - Monitoring misdirected traffic (change in AS path from tools like Looking Glass)
3. BGPSec
</details>

# Task 1
<details>

### ARP
    1. eth.src send ff...ff
    2. eth.src = 00:1d:09:f0:92:ab
    3. eth.src = 00:1a:6b:6c:0c:cc
    4. Mitm -> the ip address is at this mac address, looks very suspicious because 2 ips have the same mac, fa:16:3e:35:21:5a
### RARP filter on eth.type eq 08035
    1. RARP protocol -> 0x8035, request opcode 3
    2. RARP response opcode 4
    3. Resolved RARP, look for the target IP or the info pain
### Grat ARP (filter on arp)
    1. MAC of mach sending grad arp for ip
### CDP (filter on cdp)
    1. Look at the software version or the details pain ot get information about the version
### LLDP ( filter on lldp )
    1. Go indo Link Layer Disc Prot and look for system name
### STP
    1. Root Bridge Priority look in root idenitifier, the root birdge will have a priority of 0
    2. Look for the root bridge system to get the system that is the root bridge
### VTP
    1. vtp look in management domain, is cisco
    2. Look for revision number, pick the highest and thats the latest, 11
    3. look for vlan information and count how many are being advertised, 22
### VLAN 
    1. I pity the foom, ip.addr eq 11.22.33.44 and vlan, follow th esteam
    2. Look at the vlan id for the message
### VLAN Hopping 2
    1. Filter on VLAN, look for double tagging, the second tag is going to be the one getting attacked, 250
    2. look at the hex dump and the data being send, Wouldn't you like too be a Pepper Too!
### ICMP
    1. OS based of TTL, Prob linux ttl 64
    2. Look at the dat between each ip and icmp, look at hex dump and the daya, Exsqueeze me?
    3. Traceroute, look fhr the incrementing ttls
### Fragmented
    1. look at the IP, id feild take the decimal number 46544 
    2. look at frag offset, look at the 2nd byte and turn that to decimal to find the offset
    3. Windows -> find how payloads are differentiated to find operating system, has abcdefg
### ICMPv6
    1. 128 icmpv6 request
    2. 129 icmpv6 reply
    3. 134 for router advertisement
    4. Link layter address is inside ICMPv6 under link-layer address, fa:16:3e:35:21:5a
    5. Prefix under prefix info and look for the prefix
### HSRP 
    1. virtual address under hot standy b router protocol, look for the virtual ip address, 192.168.0.1
    2. the multicast addressed used 224.0.0.2, under ip prot, with hsrp
    3. Look for active, then there is a coup, so whatevr is before that 192.168.0.30
    4. look for the ctive one after the coup, it was on standby and become active after being advertise then shows hello and state active
### VRRP
    1. look for the destination and if its the multicast address, 224.0.0.018
    2. Look for virt router, under the IP address and it will be that ip address.
    3. how many are communicating via vrrp, go to endpoints, filter on display and find how mnany are using them
### RIP
    1. count how many there are
    2. Look at the ip address family, possibly, but loom at the ip address it is advertising and there are two different ones
    3. what transport layer, look at laye r4 and see what the port and if udp or tcp
### EIGRPv4
    1. EIGRP is based on the IP version, for find EGRIPv4 look for eigrp and ipv4, the intern route 192.168.4.0 / 24 is the one being advertied
    2. What is the IP protocol number used for EIGRP? look in IP, look for protocol, 88 is the number for it
    3. What multicast address is used to send EIGRPv4 updates?, the multicast address is 224.0.0.10
### EIGRPv6
    1. Find what net is being adverted, look at the EIGRP and internal router, its the destination
    2. What multicast address is used to send EIGRPv6 updates?, find the destination to where its senindg, ff02:a
    3. find the autonomous sytem, it is 100
### OSPF
    1. What is the IP protocol number used for OSPF? -> filter ospf, look in ip section and protoc, 89
    2. Designated router is in OSPF Hello Packets in the shortest path, 192.168.170.8
    3. look for the destination, the muilticast
### BGP
    1. look for update messages, and then look for network layer reachaivblitity, find the ips with cdrs and you get 3
    2. 10.0.0.0, 172.16.0.0, 192.168.4.0 -> just like the question above.
    3. Find the AS of peer in, look for path attributes and aggregator and find look for the originiator
    4. TCP 179 is used by BGP
## Task 2
### SMB
    1. SMB, tcp port 445
    2. file opened using smb, look for path: and then a file or file name, putty.exe
### DHCp
    1. DHCP server, look at the source and look for the DHCP server ID and look for the ID, 192.168.0.1
    2. offered ip addrss -> 192.168.0.10 look for clinet ip address to find the one that is being offered, look for the dchp offered packet as well
    3. DHCP Lease time -> in the ack or offer find the dhcp lease time: 3600
    
### DNS
    1. DNS a recordm look for a HOST (A) record for a domaiinm with .com -> microsoft.com
    2. (AAAA) dns record, wikipedia.org
    3. (MX) mail record find, hotmail.com
    4. (AXFR) zone transfer filter dns and tcp
### FTP
    1. User -> student10/password10 -> port 21
    2. follow tcp stream and find the retr DO_NOT_LOOK.txtr
    3. find ftp-data  and then find the syn syn ack -> 
    4. Look for 10.0.0.105 -> (X.X.X.X (t*256+z))
### HTTP
    1. follow the http objects and find the hostname
    2. look at http traffic and find the moved temporarily one and thats the answer
    3. 
### IMAP
    1.
    2. look at request and fetch:[x:number of files fetched]
</details>

# Day 2 - Packet Creation and Socket Programming
<details>
    
#### Socket Types
    Stram Sockets - TCP
    Datagram Sockets - UDP
    Raw Sockets - IPv4,IPv6, custom create your own packet
#### User Space bs Kernel Space Socket
1. User Spack Sockets
2.     Stream
3.     datagram
4. Kernel Space Sockets
5.     raw
#### Socket Creation and Priv Level
##### User space
    Most common, do actions on behalf of other user applications
##### Kernel Space Sockets
    Attempts to access hardware directly on behalf of user app to preven encaps/decaps or create 
    packets from scratch, needs to be elevated
##### Usr Space apps/sockets
    1.  TCP dump / wireshark to read file
    2. nmap no switch
    3. netcat to connect to listner
    4. netcate to create listner above 1024
    5. /dev/tcp /dev/udp to transmit data
##### Kernel Space 

### Python Terms
    Libraries - not installed with python, imported, imports modules
        modules - funcs, excepts, contstants, objects, types
### Network Programming with pyth 3
    import socket 
##### Socket.socket function
    socket.socket([*family*[,*type*[*proto*]]])
    family constants should be: AF_INET (default), AF_INET6, AF_UNIX
    type constants should be: SOCK_STREAM (default), SOCK_DGRAM, SOCK_RAW
    proto constants should be: 0 (default), IPPROTO_RAW
##### Librries
Socket
https://docs.python.org/3/library/socket.html
Struct
https://docs.python.org/3/library/struct.html
Sys
https://docs.python.org/3/library/sys.html

#### Demo Create Socket
##### Stream ( TCP ) ( socket.sh ) ( to recieve message: echo "message" | nc -lp 34567 )
```python
#!/bin/python3

import socket
# socketcan be used by creating socket.socket()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ipaddr = '127.0.0.1'
port = 54321

s.connect((ipaddr, port))

# to send a string as a bytes-like object, add the prefix b to string. \n is ued to go to the next line (eg hit enter)

s.send(b'Hello\n')

# it is recommended to the buffersize used recv is power of 2 and not very large number of bits

response, conn = s.recvfrom(1024)

# In order to recieve a message, that is sedn as bytes like object you must decode into utf-8 ( default)
print(response,decode())

s.close()
```
##### DGRAM ( UDP ) ( dgramex.py )
```python 
#!/bin/python3

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ipaddr = '127.0.0.1'
port = 54321

# send string as bytes like object add the prefix b to string. \n is
# to go to the  next line

s.sendto(b'Hello\n', (ipaddr,port))

#recommended buffersize used wtih recvfrom is a power of 2 and not large
response, conn = s.recvfrom(1024)

#decode defaults utf-8
print(response.decode())
```
##### Raw IPv4 Sockets
    Raw Sockets need IP header and nexc headers
    guidance from the rfc, look at rfc 791 for IPv4
 ##### Raw Socket Use Case
     Testing Specific defense mechanisms
     Avoid them
     Obfuscatea
     Create packet with chosne data in header fields
### Creating Raw Packet ( raw_packet.py )

```python
# For building the socket
import socket

# For system level commands
import sys

# Build a packet, for establishthing the packet structure. THis allows dire
ct acces to the methods
# and functions of the struct module
# alt another way to import
from struct import * 

# Create Raw Socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''

src_ip = "10.1.0.2"
dst_ip = "10.3.0.2"

# Lets add the IPv4 Header Info

ip_ver_ihl = 69 # This is putting the decimal converstations of 0x45 for ve
rsion and Internet Header Lenght
ip_tos = 0      # This combvines dscp and ecn fields
ip_len = 0      # The kernel will fill in the actual length of the packet
ip_id = 12345   # This sets the IP idenfication forthe packet
ip_frag = 0     # This sets fragmentation to off
ip_ttl = 64     # This determines the TTl of the packet when leaving the ma
chine
ip_proto = 16   # This sets the IP protocol to CHAOS (16) if this was 6 TCP
 and 17 UDP additonal headers would be required
ip_check = 0    # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip) # inet_aton(string) will convert an IP
 address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip) # same thing

# combvine into one
# "!" big endian, B = Byte H= 2 Bytes 4s = 4 Bytes
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_fr
ag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)

message = b'This is a message!'
packet = ip_header + message

# Send the packet
s.sendto(packet, (dst_ip, 0))
student@internet-host-student-4:~$ sudo python3

```
#### Raw TCP Packet ( raw_tcp.py )

```python
# For building the socket
import socket

# For system level commands
import sys

# for doing an array in the TCP checksum
import array

# Build a packet, for establishthing the packet structure. THis allows direct acces to the methods
# and functions of the struct module
# alt another way to import
from struct import * 

# Create Raw Socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''

src_ip = "10.1.0.2"
dst_ip = "10.3.0.2"

# Lets add the IPv4 Header Info

ip_ver_ihl = 69 # This is putting the decimal converstations of 0x45 for version and Internet Header Lenght
ip_tos = 0      # This combvines dscp and ecn fields
ip_len = 0      # The kernel will fill in the actual length of the packet
ip_id = 12345   # This sets the IP idenfication forthe packet
ip_frag = 0     # This sets fragmentation to off
ip_ttl = 64     # This determines the TTl of the packet when leaving the machine
ip_proto = 6   # This sets the IP protocol to CHAOS (16) if this was 6 TCP and 17 UDP additonal headers would be required
ip_check = 0    # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip) # inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip) # same thing

# combvine into one
# "!" big endian, B = Byte H= 2 Bytes 4s = 4 Bytes
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)

# TCP Header Fields
tcp_src = 54321     # Souce Port
tcp_dst = 7777      # Dest Port
tcp_seq = 454       # Sequence Number 
tcp_ack_seq = 0     # TCP ack sequence number
tcp_data_off = 5    # Data offset specifying the size of the tcp header * 4 which is 20
tcp_reserve = 0     # The 3 reserve bits +ns flag in reserve field
tcp_flags = 0       # TCP flags field before the bits are turned on
tcp_win = 65535     # Max allowd win size, reordered to network order
tcp_chk = 0         # TCP checksum which will be calculated later on
tcp_urg_ptr = 0     # Urgent Pointer only if URG flag is set

# consolidate the left shifted 4 bit TCP offset and the reserved field
tcp_off_res = (tcp_data_off << 4 ) + tcp_reserve

# TCp flags bit starting from right to left
tcp_fin = 0     # finished
tcp_syn = 1     # synchronization
tcp_rst = 0     # reset
tcp_psh = 0     # Push
tcp_ack = 0     # ack
tcp_urg = 0     # Urgent
tcp_ece = 0     # explicit congestion notifcation echo
tcp_cwr = 0     # Congestion Window Reduced

# Combine the tcp flags be lfet shiftin gthe bit locations and adding the bits together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)

# This ! in the pack format string means network order
tcp_hdr = pack('!HHLLBBHHH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win, tcp_chk, tcp_urg_ptr)
#B = 1 Bytem H = 2 Bytes, L = 4 Bytes (int)

user_data = b'Hello! Is this Hidden?'

# Pseudo Header Fields
src_address = socket.inet_aton(src_ip)
dst_address = socket.inet_aton(dst_ip)
reserved = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_hdr) + len(user_data)

# Pack the psuedo header and comvine with user data 
ps_hdr = pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
ps_hdr = ps_hdr + tcp_hdr + user_data

def checksum(data):
    if len(data) %2 != 0:
        data += b'\0'
    res = sum(array.array("H", data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

tcp_chk = checksum(ps_hdr)

# Pack the TCP Header to fill in the correct checksum - remember checksum is NOt in network byte order
tcp_hdr = pack('!HHLLBBH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win) + pack('H', tcp_chk) + pack('!H', tcp_urg_ptr)

# Combine all of the headers and the user data
packet = ip_header + tcp_hdr + user_data


# Send the packet
s.sendto(packet, (dst_ip, 0))

```
#### Encoding and Decoding       
    Encoding -> convert them to cipher
    decode -> revserse convesation process
    Common schemes UTF-8, Base64, Hex
</details>

## Task 2
<details>

### Socket Creatio0n and Packet Manipulation
    1. Address Families
        1. socket.AF_UNIX
        2. socket.AF_INET
        3. socket.AF_INET6
    2. Connections
        1. socket.connect()
        2. socket.close()
    3. Header Preparation
        1. m
    
</details>

## Day 2
<details>

#### Reconnaissance

#### Over Arching Concepts

##### Passive Reconaisance
	Gathering info without direct interation
	
	command 'whois <domain>'
	command example: 'whois google.com'
	
	command 'dig @<dnsserver> <A/AXFR/MX> <domain>'
	command 'dig <domain>' -> will give information about the ip address, info about type of service, ips
	
	command example: 'dig google.com'
	command example: 'dig @ns1.google.com AXFR google.com'
	command example: 'dig @<dns> A/AAAA/MX/SOA/TXT google.com
	
	Practice Example to Use for Dig
	dig @nsztml.digi.ninka AXFR zonetransfer.me
	
##### Ways to Do stuff
	wayback machine, take snapshot of website and the stuff about the website, whats changed
	
	Google Searches
		Subdomains
			In google search: site:<domain> <command>
			Examples:
				site:ccboe.net intext."@ccboe.net" -> look if you can write emails to them
				site:google.com filetype:pdf "policy" "password"	
	Google Dorking "Cheat Sheet"

##### SHODAN
	Database, crawls web, find publicly avilable hosts that are vulnerable
##### whatsmyname.app
	social engineering tool

#### Network Scanning
	Strategies
		-Remote to local, local to remote, local to local, remote to remote

	Approach
		Aim
			wide range scan
			target scan
		Method
			 Single Source Scan
			 Distributed Scan
	Types of Scanning
		-Broadcast / Ping Sweep
		-SCANS
			ARP, SYN, Full connect, Fin, XmAS, UDP, idle (zombie)
			ACK/Win Scan
			RPC, FTP, decoy, OS fingerprint, version, Protocol Ping, Disovery Probes

```
#!/bin/bash
echo "Enter network address (e.g. 192.168.0): "
read net
echo "Enter starting host range (e.g. 1): "
read start
echo "Enter ending host range (e.g. 254): "
read end
echo "Enter ports space-delimited (e.g. 21-23 80): "
read ports
for ((i=$start; $i<=$end; i++))
do
    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
done
# (-v) running verbosely (-v on Linux, -vv on Windows),
# (-n) not resolving names. numeric only IP(no D.S)
# (-z) without sending any data. zero-I/O mode(used for scanning)
#(-w1) waiting no more than 1second for a connection to occur
# (2>&1) redirect STDERR to STDOUT. Results of scan are errors and need to redirect to output to grep
# (-E) Interpret PATTERN as an extended regular expression
# ( | grep open) for Debian to display only open connections
# ( | grep succeeded) for Ubuntu to display only the open connections
```

10.50 -> environment is a floating IP address, public IP address, hosts that need to communicate with a lot of other hosts
have the ip address

### Scanning Script Examples
	Example 1
		Enter network address (e.g. 192.168.0): 
		10.50.30
		Enter starting host range (e.g. 1): 
		212
		Enter ending host range (e.g. 254): 
		212
		Enter ports space-delimited (e.g. 21-23 80): 
		21-23 80
		(UNKNOWN) [10.50.30.212] 22 (ssh) open
		(UNKNOWN) [10.50.30.212] 21 (ftp) open
		(UNKNOWN) [10.50.30.212] 80 (http) open
		student@internet-host-student-4:~$ nc 10.50.30.212 21
		220 ProFTPD Server (Debian) [::ffff:10.0.0.101]
		student@internet-host-student-4:~$ nc 10.50.30.212 23
		(UNKNOWN) [10.50.30.212] 23 (telnet) : Connection refused
		student@internet-host-student-4:~$ nc 10.50.30.212 80
		GET /
		<html>
		<a href="./web.png">web.png</a>
		</html>
	Example2
		student@internet-host-student-4:~$ ./scan.sh 
		Enter network address (e.g. 192.168.0): 
		10.50.30
		Enter starting host range (e.g. 1): 
		212
		Enter ending host range (e.g. 254): 
		212
		Enter ports space-delimited (e.g. 21-23 80): 
		1-1023
		(UNKNOWN) [10.50.30.212] 443 (https) open
		(UNKNOWN) [10.50.30.212] 80 (http) open
		(UNKNOWN) [10.50.30.212] 25 (smtp) open
		(UNKNOWN) [10.50.30.212] 22 (ssh) open
		(UNKNOWN) [10.50.30.212] 21 (ftp) open
		student@internet-host-student-4:~$ nc 10.50.30.212 25
		SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
		^C
		student@internet-host-student-4:~$ nc 10.50.30.212 443

		As you are starting to notice, not all ports are hosting the services they would normally.

#### nmap -A -T4
	nmap -A -T4 --min-rate 10000 -vvvv 10.50.30.212,<ip> -p <port,port2,port-range> -> be default scans the top 1000 most commonly used ports
	
#### FTP Server
		wget -r ftp://10.50.30.212
			-r -> recuruse
			command downloads to host
			cant connect to the private ip adrress on the inside
			
		--2023-07-12 14:09:43--  ftp://10.50.30.212/
			   => ‘10.50.30.212/.listing’
		Connecting to 10.50.30.212:21... connected.
		Logging in as anonymous ... Logged in!
		==> SYST ... done.    ==> PWD ... done.
		==> TYPE I ... done.  ==> CWD not needed.
		
#### Web sever
		wget -r 10.50.30.212
		student@internet-host-student-4:~$ ls 
		10.50.30.212
		ls 10.50.30.212/
		index.html  web.png
		student@internet-host-student-4:~$ cat 10.50.30.212/index.html 
		<html>
		<a href="./web.png">web.png</a>
		</html>
		student@internet-host-student-4:~$ eom 10.50.30.212/web.png 

	 Web Server Altnate Port
		wget -r ftp://10.50.30.212:<PORT>

#### SSH
	ssh bob@10.50.30.212 -p 25
	important commands for network related info
		ip addr
			command gives info on the port and address
		ip neigh 
			arp information
		ip route
			default gateway
			routing information
		ss -ntulp
			replaces netstat
	Random Important commands
		sudo -l : lists what you can sudo
	ls /usr/share/ctcc
	Important Files
		/etc/services
		/etc/hosts -> dns host records
	
	Important commands
		hostname
		hostname -f (FQDN) tells the domain that the current user is in
	
	To Capture All Packets
		Promiscious mode
	
	Dont Worry About Saving the Network maps
	
		
</details>

## Task 3 - Network Recon
<details>

### Enumeration

	from internet-host
 		ssh vyos@172.16.120.1
   		dig TXT networking-ctfd-1.server.vta
     			FLAG: cmVhZHlfc2V0X3NjYW4= -> Ready Set Scan

  	from vyos 172.16.120.1
   		Hostname: RED-SCR
 
</details>

## Data Transfer
<details>

### Data Tranfering Protocols
	1. TFTP
    	2. FTP
     	   -Active
       	   -Passive
	3. SFTP
	4. SCP

#### TFTP
 	Trivial
  	UDP port 69
   	Desc: small and simple, no terminal comms, 
    	Encrpy: insecure, used often for tech such as BOOTP and PXE
#### FTP
	File Tranfer
 	TCP Port 20/21
  	Encryp: none, insecure
   	Interactive Terminal

 	Active vs Passsive FTP
  		Pizza Deliverd vs Picking Up Pizza
##### 	Active FTP (Pizza Delivered)
	Client comms with sever, I want this file
 	Server from port 20, send traffic to random high port on client
  	If firewall is in place, cant get delivered

##### 	Passive FTP (Pizza Pickup)
	I want file
 	on random high port, client picks up from port, go get file
  	
#### SFTP
	SSH FTP
 	TCP Port 22
  	Encrypted
   	Symmetric and asymmetric encryption, functions like ftp but only goes over port 22
    	FTP over SSH
     	Interactive terminal

### FTPS
	FTP Secure
 	Adds SSL/TLS to ftp
  	TCP Port 443
   	Aithneticaion wi username / password
    	Interactive terminal access
     	Implicit: Connection Encrypted at all times
     		Port 999 Control
      		Port 989 Data
       	Explicit Port 21, specifcy secure or insecure connection

#### FTP Demo
	ftp 10.0.0.33
 	Anonyomous
	ftp <ip>
 	commands
  		help
    		lcd / -> local dir is / on local computer
      		get <file> : get file from the ftp server
		put <file> : put file on the ftp sercer

#### SCP
	Secure Copy Protocol
 	TCP port 22
  	Syymetric and asymmetric encryption, non interactive, auth through sign in

    	Syntax:
     		scp [-r "recurse"] [-P <port>] <source> <destination> 
	Example:
 		scp <local/file> <ip:dest> : local
   		scp <ip:dest> <local/file> : dest
	
	3 Way SCP
 	scp -3 <source> <dest> : for three way if someone doesnt have auth to another

##### Demo
	IHOST: talk with both
 	Toby-Host: cant talk w claire
  	Claire-Host: cant talk w toby

 	From Host to Remote
   	Ihost> scp test.txt toby@toby-host: ": is home dir to user"
    	Ihost> scp test.txt toby@toby-host:files/ ":files/dir"
     	Ihost> scp test.txt toby@toby-host:/opt "abs path"
      	Ihost> scp -P 2222 test.txt claire@claire-host:files/ ":, home dir"
       	Ihost> scp -r -P 2222 /etc/ssh claire@claire-host:sshconfigs 

 	From Remote to Host
  	Ihost> scp toby@toby-host:.bash_profile . "dest of . put is in our home dir"

    	From Remote to Remote (not auth) 3 way
     	Ihost> scp -3 -r claire@claire-host:/etc/ssh toby@toby-host:sshconfigs/

#### SCP (Tunnel)
		ssh student@172.16.82.106 -L 1111:localhost:22 -NT
 		scp -P 1111 student@localhost:secretstuff.txt /home/student

	Upload a file to a remote directory from a local directory

		scp -P 1111 secretstuff.txt student@localhost:/home/student


#### NC
	Used for banner grapping, port scanning
 	altnerate uses, chat server

###### Two Way listner
   	nc can function as a client or a server,
    	Need to have listner first

     	john> nc -lp 2222

       	student> nc <johnip> 2222

 	Can have convo to each host

###### Send contents of a file
	nc <remoteip> <port> < file
 	nc -l -p 2222 > file 
###### Edite File no perm to
	sudo vim -> allow to do anything, can also run commands
 	EDITOR=/usr/bin/vim
  	sudoedit 
	nc -lp 2222 -e /bin/bash gives shell

 	sudo vim
  	nc -lp 2222 -e /bin/bash

   	nc <ip> <port>
    	priv escalation
#### Netcat relay (2 dist ends than talk, middle can)
	two types of pipes, named and unamed
	named pip used for unrelated process, to share data

 	mknod mypipe p -> make named pipe
  	mcfifo my pipe -> make named pipe
   	ls -l -> see file that is my pipe, file pipe and shows its a pipe

 	All needs is client and listner on either side
     	nc -lp 3333 0<mypipe | nc -lp 3334 1>mypipe

      	one side
       	nc 10.10.0.40 3333

 	other side
  	nc 10.10.0.40 3334 
####  File Tranfer via /DEV/TCP
	/dev/tcp/<ip>/<port>
	
### Task

#### Relay 1

<details>

	T1: Int-Host : 10.10.0.40 outside ip
 		Relay
   			nc -lvvp 1234 0<relay1 | nc -lvvp 1234 1>relay1 # make netcat relay listnening on the port 1234 specified
		Get file from T2 to Host
  			nc -lp 5555 > 1steg.jp
     			steghide extract -sf 1steg.jp
  			cat phrase1.txt | md5sum
  	
  	T2: Relay : 172.16.40.10 : Blue-Int-Dmz-Host-4 
		Relay  		
     			T1: ssh into 172.16.40.10
	    		nc -lp 1234 >1steg.jpg
      		Get file to Host
			nc -lp 10.10.0.40 5555 < 1steg.jpg
   		
 	T3: 172.16.82.115 : BLUE_HOST-4
  		No Creds
</details>

</details>

# Lesson 4 - Data Transfer, Movement, and Redirection

<details>

## SSH
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/5390a5c2-52f9-4c8c-891c-68e1d0b754a2)

 	Secure Shell
  	File Locations
   		cd ~/.ssh -> has known keys and authorizaions
    			authorized_keys -> dont have to enter password
      			known_hosts -> base64 encoded, is the servers that have logged into in the past 
		/etc/ssh
  	Two types of encryption with SSH
   		Initial is Assymetric
     		Shared Session to Encrypt data is symmetric

## Port Forwarding ( Local and Remote )
	Only thing changes, is where the port is opening from 
	
### Local
##### Syntax
 	ssh -p <optional alt port> <user>@<hostname/ip> -L <local-port>:<tgthostname-ip>:<tgt port>
	ssh -L <local,port>:<tgt:hostname-ip>:<tgt port> -p <alt port> <user>@<pivot ip> -NT
##### Local Port Forward Demo

Port Range : 17200 - 17299
 
Opened port is local to the host
Traffic is being forwarded to toby host
Map it, draw opened port, what host:what port is forwarding traffic to
Test Port Forward
Put -NT non interactive to make sure it doesnt get fuckkeddd up

###### Demo 1 -> Traffic through another
 	ihost> ssh toby@tobyhost -L 17200:127.0.0.1:80   
  	ihost> wget -r 127.0.0.1:17200

###### Demo 2 -> Forward Traffic To John Host
	ihost> ssh toby@toby-host -L 17201:john-host ip:1111
	ihost> ssh -p 17200 john@127.0.0.1
 	Jhost> 
 
	SSH Local Port Forwarding

 
	    Creates a local port (1111) on the local host that forwards to a target machine’s port 80.
	
	ssh student@172.16.82.106 -L 1111:localhost:80 -NT
	
	or
	
	ssh -L 1111:localhost:80 student@172.16.82.106 -NT
	
	SSH Local Port Forwarding Through a Local Port

###### Demo 3
if you reuse port will cause problem

 	ssh john@10.50.23.66 -L 17200:10.0.0.103:80 -NT
 	ssh john@10.50.23.66 -L 172090:10.0.0.103:22 -NT
  	
   	wget -r 17200:1270.0.0.1
   	ssh -p 17200 mike@127.0.0.1

	ssh john@10.50.23.66 -L 17200:127.0.0.1:22 -NT
 	
     
###### Slide Demo
	Internet Host:
	ssh student@172.16.1.15 -L 1111:172.16.40.10:22 -NT
	ssh student@localhost -p 1111 -L 2222:172.16.82.106:80 -NT
#### Web Sevice
Not just use wget, so can use firefox

	firefox localhost:2222
	
	    Creates an additional local port on the local host that forwards to a target machine through the previous channel created.
	
	SSH Dynamic Port Forwarding
	
	    Syntax
	
	ssh -D <port> -p <alt port> <user>@<pivot ip> -NT
	
	    Proxychains default port is 9050
	
	    Creates a dynamic socks4 proxy that interacts alone, or with a previously established remote or local port forward.
	
	    Allows the use of scripts and other userspace programs through the tunnel.
	
	SSH Dynamic Port Forwarding 1-Step
	
	Blue Private Host-1:
	ssh student@172.16.82.106 -D 9050 -NT
	
	proxychains ./scan.sh
	proxychains ssh student@10.10.0.40
	
	SSH Local and Dynamic Practice
	7.1
	SSH Local Port ForwardingSyntaxssh -p <optional alt port> <user>@<pivot ip> -L <local bind port>:<tgt ip>:<tgt port> -NT
	or 
	ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<pivot ip> -NT

 
### Remote Port Forwardidng
Who local host is changes, at all times, have to start at port forward
Asks the remote host to open 17299 on john
John will send to that loopback:3443  

	Chost(telnet)> ssh -p 1111 john@john-host -R 17299:1270.0.1:3443 -NT
 	Ihost> ssh -p 17200 john@127.0.0.1
  	Jhost> ssh -p 18299 carlton@127.0.0.1
   	Chost(ssh)>

    	ihost> ssh -p 17200 john@127.0.0.1 -L 17202:127.0.0.1:17299 -NT 
     	ihost> ssh -p 17202 carlton@127.0.0.1
  	
### Dynamic Port Forwarding
It is just for TCP Traffic, no udp or icmp
Must be SSH Port, cannot tunnel on non ssh ports

   	Proxychain defualt port is 9050
	Ihost> ssh -p 17202 carlton@127.0.0.1 -D 9050 -NT
	Ihost> proxychains wget -r jez-host
 				/
	 Ihost> proxychains telnet/ssh
 proxychains./scan.sh -> nmap/wget/ftp
 
 Whatever run through proxychain is coming out of carstlon
 Using Proxychains, can scan hosts, obfuscation
 	
</details>

### Task 2 
<details>

### Task 2

 	5. C
  	6. A. ssh -L 1111:localhost:22 cctc@10.50.1.150 -NT 
   	7. B. ssh cctc@10.50.1.150 -L 1111:localhost:80 -NT 
	8. D
 	9. C
  	10. B
   	11. 
 
</details>

# NEED THIS SCAN!
nmap -sT -T4 --min-rate 100000
tcpdump -X icmp

# Network Analysis ( July 8th )

<details>

## Passive
	Just looking at normal traffic and finding out whats going on
### p0f
	which p0f
 	sudo /etc/p0f/p0f.fp which looks at traffic and analysizes it
  	can find os and what routers are being used
## Network Traffic Baselining
	Snapshot what looks like at a time frame
 	7 days to establish snapshot
	- Networks are dynamic, got ot find baseline to find normalzies
	- Find protocols that are allowed the network

## TCP and Wireshark
### For NMAP SCAN
	sudo tcpdump -r <file> "tcp[13] = 0x02"
	Find IPS 
 		sudo tcpdump -r <file> "tcp[13] = 0x02" | awk '{print $3}' | cut -d. =f1,2,3,4 | sort | uniq -c
   	Find Ports 
    		sudo tcpdump -r <file> "tcp[13] = 0x02" | awk '{print $5}' | cut -d. =f1,2,3,4 | sort | uniq -c
### Network Data Types
	There are different kinds of data
 	Full, Session, Alerts and Logs
## Data Collection Devies
	Sensors in line or passive
## Data Collection	
	TAP capturing, SPAN rotuing switch and software dupliction, can lose packets, MiTM 
## Anomaly Detection
	Indicator of Attack
 		Proactive, find sus activities, find intent
   	Indicator of Compramise
    		Reactive, forensic evidence, info can change
### Indicators
	.exe, NOP sled, sigs, traffic
 	Scans, DMZs, Malware Reinfection
  	Reinfection -> someones probably network
   	Unsual traffic
### Decode
	Data is not always going to be in plain text

 </details>

 # Task 4
  <details> 

	1-3. find ip addresses, find hosts, sudo tcpdump -r attack_analysis1.pcap | awk '{print $3,$5}' | egrep -o "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]|[0-9])\.){1,3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]|[0-9])" | sort -n | uniq

 	4. find transport layer protocols
  		sudo tcpdump -r attack_analysis1.pcap "ip[9] =0x11 " | wc -l
	6. GPRS
 	7. 
    
  
  </details>

# Network Traffic Filtering

<details>

## Applications
	Filter traffic, block certain things
 		-emails, tools, only allow certain computers to access network, network traffic
## Devices to Filter
	Routers, Proxy Server, Switch, Pretty much at every layer

## Filtering Concepts
   	Whitelist -> Block all, must allow certain things
    	vs
     	Blacklist -> Allows all, must block certain things

       	Network Device Operation Modes
		Router -> everyone can see it
  		Transparent -> Stealth mode for firewall
## Filtering Concepts pt. 2
	IDS -> Alarm
 	IPS -> Must be set up in line, should block things if working right
  	Firewalls
   		stateless -> Packets
     		stateful -> track based of flags, the state of it
 		application -> filters on applications like emails
## Traffic Directions
	loc host -> remote vice versa, either inbound or outbound

## Netfilter Framework
	packet filter, stateless / stateful, NAT and PAT
 	Hook
  		prerouting, input, forward, output, postrouting
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/1a6a0a15-5c04-4765-8a60-cca82c7f08a3)

## Config IP Tables 
	which IP Tables, need elivated privs, sudo 
``` shell
iptables -t [table] -A [chain] [rules] -j [action]

Rules:

-i or -o [iface]
-s or -d [ip.add | network/mask]
-p [protocol(in ipv4 header)]

-m is used with:
  state --state [state]
  mac [--mac-source | --mac-destination] [mac]
  tcp | udp [--dport | --sport] [port | port1:port2]
  multiport [--sports | --dports | --ports]
                [port1,[port2,[port3:port15]]]
  bpf --bytecode [ 'bytecode' ]

[action] - ACCEPT, REJECT, DROP
```

## IP Tables Demo
	sudo iptables -t <table> -L (list)
 	-F -> flush, does not change default policy
  	-A <chain> -p <layer4protocol> --dport <port> -j <action> -> add rule, input or output chains
   	
```shell
Allow SSH
	sudo iptables -F
	sudo iptables -A INPUT -p tcp --dport22 -j ACCEPT
	sudo iptables -A OUTPUT -p tcp --src22 -j ACCEPT
	sudo iptables -L
	sudo iptables -A INPUT -p tcp --sport22 -j ACCEPT
	sudo iptables -A sudo -p tcp --dport22 -j ACCEPT

Drop all INput
	sudo iptables -A INPUT -j DROP

Allow X11 Forwarding (Terminator)
	sudo iptables -A INPUT -p tcp -m multiport --ports 6010,6011,6012 -j ACCEPT
	sudo iptables -A OUTPUT -p tcp -m multiport --ports 6010,6011,6012 -j ACCEPT

See Line Numbers
	sudo iptables -L -n --line-numbers

PING
	sudo iptables -A INPUT -p ICMP --icmp-type <code> -j ACCEPT

Delete Rule
	sudo iptables -D INPIT <rule number>, list is dynamic

	sudo iptables -P (policy) <chain> <action>
```
## NFT

```shell
nft add table [family] [table]

[family] = ip, ip6, inet, arp, bridge and netdev.

[table] = user provided name for the table.
nft list table [family] [table] [-a]

    Adds after position

    nft add rule [family] [table] [chain] [position <position>] [matches (matches)] [statement]

    Inserts before position

    nft insert rule [family] [table] [chain] [position <position>] [matches (matches)] [statement]

    Replaces rule at handle

    nft replace rule [family] [table] [chain] [handle <handle>] [matches (matches)] [statement]

    Deletes rule at handle

    nft delete rule [family] [table] [chain] [handle <handle>]

	sudo nft add chain <family> 
	sudo nft add chain ip Wev INput { type filter hook input priority 0\; policy accept\; }
	sudo nft add chain ip Wev OUTput { type filter hook output priority 0\; policy accept\; }
	
	sudo nft add rule ip Wev INput tcp dport 22 accept
	sudo nft add rule ip Wev INput tcp sport 22 accept
	sudo nft add rule ip Wev OUTput tcp sport { 21,22,23,80 } accept
	sudo nft add rule ip Wev INput tcp dport { 6010,6011,6012 } accept
	sudo nft add rule ip Wev OUTput tcp sport { 6010,6011,6012 } accept

accept before flush
	sudo nft add chain ip Wev { type filter hook input priority 0\; policy accept\; }
	sudo nft flush ruleset, sudo nft flush table ip Wev
	sudo nft list ruleset 
```
## NAT & PAT 
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/c3f9bb21-427d-48b2-aeff-104b77f0128b)

### Source NAT W/ IPTABLES

![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/4bb8ebe8-18e4-457e-9e16-7a51f017cbf9)
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 1.1.1.1

### Destination NAT W/ IPTABLEs
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/05bff57d-661a-4efe-a1f0-5d1f004716ca)
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 10.0.0.1

### Source PAT W/ IPTABLES
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/92e67e3a-a33f-4a3c-8e22-8a188ec03dc9)
iptables -t nat -A POSTROUTING -p tcp -o eth0 -j SNAT --to 1.1.1.1:9001

### Destination PAT W/ IPTABLES
![image](https://github.com/HassettJM2002/Network-Fundamentals/assets/134302854/af276564-00d0-437c-8898-34d69fc2b17b)
iptables -t nat -A PREROUTING -p tcp -i eth0 -j DNAT --to 10.0.0.1:8080

## NAT DEMO
```shell
	nft add table ip NAT
	nft add chain ip NAT POSTROUTING {type nat hook postrouting priority 100 \; }
```
#### Source NAT
```shell
    nft add rule ip NAT POSTROUTING ip saddr 10.1.0.2 oif eth0 snat 144.15.60.11
```
#### Destination NAT
```shell
    nft add rule ip NAT PREROUTING iif eth0 tcp dport { 80, 443 } dnat 10.1.0.3
```
#### Source NAT w/ masquerade
```shell
    nft add rule ip NAT POSTROUTING ip saddr 10.1.0.0/24 oif eth0 masquerade
```
#### Destination NAT (port forwarding) with redirect
```shell
    nft add rule ip NAT PREROUTING tcp dport 80 redirect to 8080
```

</details>

## Exercizes

<details>

##### Task 1
	sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -m multiport --ports 22,23,3389,80 -j ACCEPT
 	sudo iptables -P OUTPUT DROP
	sudo iptables -A OUTPUT -p ICMP --icmp-type 0 -j ACCEPT
	sudo iptables -A OUTPUT -p ICMP --icmp-type 8 -j ACCEPT
 
	sudo iptables -P FORWARD DROP
  
  	sudo iptables -A INPUT -p tcp -m state --state NEW,ESTABLISHED -m multiport --ports 22,23,3389,80 -j ACCEPT
	sudo iptables -P INPUT DROP
 	sudo iptables -A INPUT -p ICMP --icmp-type 0 -j ACCEPT
	sudo iptables -A INPUT -p ICMP --icmp-type 8 -j ACCEPT
 
##### Task 2
	input
		type filter hook input priority 0; policy accept;
				tcp sport { 22, 23, 3389 } ct state { established, new } accept # handle 12
				tcp dport { 22, 23, 3389 } ct state { established, new } accept # handle 15
				icmp code 8 ip saddr 10.10.0.40 accept # handle 29
				icmp code 0 ip saddr 10.10.0.40 accept # handle 30
				tcp sport { 5050, 5150 } accept # handle 32
				tcp dport { 5050, 5150 } accept # handle 34
				udp sport { 5050, 5150 } accept # handle 36
				udp dport { 5050, 5150 } accept # handle 38
				tcp sport { 80 } ct state { established, new } accept # handle 49
				tcp dport { 80 } ct state { established, new } accept # handle 52


	output
		type filter hook input priority 0; policy accept;
		tcp sport { 22, 23, 3389 } ct state { established, new } accept # handle 19
		tcp dport { 22, 23, 3389 } ct state { established, new } accept # handle 22
		icmp code 8 ip daddr 10.10.0.40 accept # handle 26
		icmp code 0 ip daddr 10.10.0.40 accept # handle 28
		tcp sport { 5050, 5150 } accept # handle 40
		tcp dport { 5050, 5150 } accept # handle 42
		udp sport { 5050, 5150 } accept # handle 44
		udp dport { 5050, 5150 } accept # handle 46
		tcp sport { 80 } ct state { established, new } accept # handle 55
		tcp dport { 80 } ct state { established, new } accept # handle 58


</details>
