# Dataplane Router

Dataplane Router is a network router implementation in C/C++ that focuses on the data plane functionality. It is designed to forward IPv4 packets efficiently by leveraging a static routing table, dynamic ARP resolution, and ICMP messaging for error and echo responses.

## Overview

In this project, the router’s dataplane is implemented while the control plane is assumed to be handled separately. The dataplane is responsible for actually directing packets based on entries in a pre-populated routing table. The router supports multiple interfaces and processes incoming packets on any interface according to Ethernet, IPv4, ARP, and ICMP protocols.

## Features

- **Packet Parsing and Validation:**  
  Parses raw byte streams to extract Ethernet, IP, ARP, and ICMP headers. Invalid or malformed packets are discarded.

- **ARP Resolution and Caching:**  
  Implements dynamic ARP resolution. When a required next-hop MAC address is missing from the ARP cache, the router queues the packet, sends an ARP request, and processes queued packets once the ARP reply is received.

- **IPv4 Packet Forwarding:**  
  Uses a static, pre-populated routing table to determine the best next-hop for incoming IPv4 packets.  
  - Performs checksum verification and TTL validation.  
  - Decrements TTL and recalculates the checksum for forwarded packets.

- **ICMP Message Generation:**  
  Generates ICMP messages for echo requests, time exceeded errors (TTL expiration), and destination unreachable scenarios.

- **Longest Prefix Match (LPM):**  
  The router employs a binary search over a sorted routing table to perform longest prefix matching and determine the most specific route for packet forwarding.

## Implementation Details

- **Dataplane Focus:**  
  The implementation strictly handles the dataplane portion of the router. The routing table is provided as a static input file and remains unchanged during runtime.

- **Packet Handling Flow:**  
  1. **Parsing & L2 Validation:**  
     - The Ethernet header is examined to ensure that packets are addressed either directly to the router's interface or to broadcast.
  2. **Protocol Determination:**  
     - Based on the EtherType, packets are classified as either IPv4 or ARP.
  3. **IPv4 Processing:**  
     - Checks if the packet is destined for the router. If so, it processes ICMP echo requests.  
     - For packets meant for forwarding, the router validates the IP checksum, decrements TTL (and sends an ICMP "Time Exceeded" message if TTL expires), and recalculates the checksum.
     - A binary search (Longest Prefix Match) is used to look up the best route in the routing table.
  4. **ARP Resolution:**  
     - If the next-hop MAC address is not in the ARP cache, the packet is temporarily queued and an ARP request is initiated.
     - Upon receiving an ARP reply, the ARP cache is updated and all queued packets destined for that next-hop are forwarded.
  5. **ICMP Processing:**  
     - The router generates appropriate ICMP error messages (e.g., destination unreachable) when necessary.

- **Protocol Header Structures:**  
  - **Ethernet Header:** Contains destination and source MAC addresses and EtherType.
  - **IPv4 Header:** Includes fields such as version, header length (IHL), type of service (TOS), total length, TTL, protocol identifier, checksum, and source/destination IP addresses.
  - **ARP Header:** Follows RFC 826 format with hardware type, protocol type, hardware and protocol lengths, opcode, and sender/target addresses.
  - **ICMP Header:** Used for echo requests/replies and error messages, with type, code, checksum, and additional fields depending on the message type.

## Performance Optimizations

- **Sorted Routing Table & Binary Search:**  
  By sorting the routing table entries based on network mask and prefix, the router can utilize binary search for Longest Prefix Match, ensuring fast lookup even with a large number of entries (up to 100,000).

- **Selective Queueing:**  
  Instead of dropping packets when ARP resolution is required, packets are temporarily stored in a queue. This minimizes packet loss and avoids unnecessary retransmissions, improving overall network performance.

- **Minimal Packet Processing:**  
  The dataplane only handles packet forwarding and error generation, offloading complex routing algorithms to the control plane. This separation allows for lightweight and fast packet processing.

## Technical Details

- **Programming Language:**  
  Implemented in C/C++ using standard libraries such as `<stdlib.h>`, `<stdio.h>`, `<string.h>`, and `<arpa/inet.h>`.

- **Network Byte Order:**  
  All header fields are handled in network byte order; conversion functions like `htons()` and `ntohl()` are used to correctly process multi-byte fields.

- **Memory Management:**  
  Dynamic memory allocation (using `malloc()` and `calloc()`) is used for packet buffers, routing and ARP tables, and packet queues. Appropriate error handling ensures robust operation.

- **Layered Architecture:**  
  The router interacts with lower network layers using a level 2 API to send Ethernet frames over a physical Ethernet connection.

---

This project serves as a comprehensive demonstration of a router's dataplane, showcasing how core networking protocols are implemented to efficiently forward packets while dynamically managing ARP resolution and providing ICMP functionality.
