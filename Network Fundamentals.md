# CCTC Networking
##### Home for the Section https://net.cybbh.io/public/networking/latest/index.html
##### Day 1 Repos: https://net.cybbh.io/public/networking/latest/lesson-1-fundamentals/fg.html
## Day 1 - Network Fundamentaks

#### Basics
#####
    bits -> 0 / 1, on or off
    byte -> 8 bits -> 0 -> 255

#### Base n formats
    Base 2 (Binary) -> 0 - 1 
    Base 10 (Decimal) -> 0 - 9
    Base 16 (Hexidecimal) -> 0 - F  

### OSI Model Brief Overview
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
###### 
## Day 2

