# CCTC Networking
##### https://net.cybbh.io/public/networking/latest/index.html
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
#### Layer 5: Session
#### Layer 6: Presentation
#### Layer 7: Application

## Day 2

