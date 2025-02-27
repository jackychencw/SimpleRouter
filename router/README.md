# Simple Router

CSC458 Assignment1 Fall 2019
Team members: Ziqi Chen, Ben Wong

## Description
A simple router that receives Ethenet frames, processes packets by handling ARPs, IP, TCP/UDP, and ICMP packets, and forwards them to correct interface. The project runs on top of mininet.

## Requirements
The router must successfully route packets between the Internet and the application servers.
The router must correctly handle ARP requests and replies.
The router must correctly handle traceroutes through it (where it is not the end host) and to it (where it is the end host).
The router must respond correctly to ICMP echo requests.
The router must handle TCP/UDP packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.
The router must maintain an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).
The router must queue all packets waiting for outstanding ARP replies. If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
The router must not needlessly drop packets (for example when waiting for an ARP reply)
The router must enforce guarantees on timeouts–that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router.