# CCTC Networking

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
#### Layer 3: Network
#### Layer 4: Transport
#### Layer 5: Session
#### Layer 6: Presentation
#### Layer 7: Application

## Day 2

