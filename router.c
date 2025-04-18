#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ETHERTYPE_IP 0x0800
#define MAC_SIZE 6
#define TTL 64

#define ICMP_ECHO          0
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DEST_UNREACH  3

/**
 * @brief Compares two route table entries based on their masks and prefixes.
 *
 * This function is used to compare two entries in the routing table in order
 * to sort them. It first compares the netmasks (after converting them to host order).
 * If the masks are equal, it then compares the prefixes (after applying the mask).
 *
 * @param a Pointer to the first route table entry.
 * @param b Pointer to the second route table entry.
 * @return
 *         - Returns 1 if the first entry is considered greater.
 *         - Returns -1 if the first entry is considered less.
 *         - Returns 0 if both entries are equivalent.
 */
int compare_masks(const void *a, const void *b) {
    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    uint32_t mask1 = ntohl(entry1->mask);
    uint32_t mask2 = ntohl(entry2->mask);

    if (mask1 > mask2) {
        return 1;
    } else if (mask1 < mask2) {
        return -1;
    } else {
        uint32_t prefix1 = ntohl(entry1->prefix) & mask1;
        uint32_t prefix2 = ntohl(entry2->prefix) & mask2;
        if (prefix1 > prefix2) {
            return 1;
        } else if (prefix1 < prefix2) {
            return -1;
        } else {
            return 0;
        }
    }
}


/**
 * @brief Finds the best matching route for a given destination IP using binary search.
 *
 * This function searches through the sorted routing table (in ascending order by mask)
 * to find the best matching route for the specified destination IP address. It uses
 * binary search, ensuring a logarithmic time complexity. The matching is based on the
 * longest prefix match (LPM) principle.
 *
 * @param ip_dest The destination IP address in network byte order.
 * @param rtable_len The number of entries in the routing table.
 * @param rtable Pointer to the array of route table entries.
 * @return struct route_table_entry* Pointer to the best matching route entry.
 *         Returns NULL if no matching route is found.
 */
struct route_table_entry *get_best_route(uint32_t ip_dest, int rtable_len, struct route_table_entry *rtable) {
    int low = 0, high = rtable_len - 1;
    struct route_table_entry *best_match = NULL;

    uint32_t ip_dest_host = ntohl(ip_dest);

    while (low <= high) {
        int mid = low + (high - low) / 2;
        uint32_t prefix = ntohl(rtable[mid].prefix);
        uint32_t mask = ntohl(rtable[mid].mask);
        uint32_t masked_ip = ip_dest_host & mask;

        if (masked_ip == prefix) {
            best_match = &rtable[mid];
            low = mid + 1;
        } else {
            if (masked_ip < prefix) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
    }

    return best_match;
}




/**
 * @brief Constructs an ICMP packet with Ethernet and IP headers.
 *
 * Builds an ICMP packet for a given ICMP type by encapsulating it within an Ethernet
 * and an IP header. The Ethernet header sets the destination MAC to the original source MAC
 * and the source MAC to the router's MAC. The IP header is set with version 4, default TTL,
 * protocol ICMP, and a checksum computed over the header. The ICMP header is configured with
 * the specified type and a checksum.
 *
 * @param orig_eth Pointer to the original Ethernet header.
 * @param orig_ip Pointer to the original IP header.
 * @param router_mac Pointer to the router's MAC address.
 * @param router_ip The router's IP address (network byte order).
 * @param icmp_type ICMP message type (e.g., ICMP_ECHO).
 * @return char* Pointer to the allocated packet buffer. Caller must free it.
 */
char* build_icmp_packet(const struct ether_hdr *orig_eth,
                        const struct ip_hdr *orig_ip,
                        const uint8_t *router_mac,
                        uint32_t router_ip,
                        uint8_t icmp_type) {
    size_t packet_size = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
    char *packet = malloc(packet_size);
    if (!packet) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    memset(packet, 0, packet_size);
    // Set Ethernet header
    struct ether_hdr *eth = (struct ether_hdr *)packet;
    memcpy(eth->ethr_dhost, orig_eth->ethr_shost, MAC_SIZE);
    memcpy(eth->ethr_shost, router_mac, MAC_SIZE);
    eth->ethr_type = htons(ETHERTYPE_IP);
    // Set IP header
    struct ip_hdr *ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    ip->ihl = 5;
    ip->ver = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
    ip->id = htons(0);
    ip->ttl = TTL;
    ip->proto = 1; // ICMP
    ip->source_addr = router_ip;
    ip->dest_addr = orig_ip->source_addr;
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
    // Set ICMP header
    struct icmp_hdr *icmp = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    memset(icmp, 0, sizeof(struct icmp_hdr));
    icmp->mtype = icmp_type;
    icmp->mcode = 0;
    uint16_t csum = checksum((uint16_t *)icmp, sizeof(struct icmp_hdr));
    icmp->check = htons(csum);

    return packet;
}


/**
 * @brief Generates and sends an ARP reply.
 *
 * This function modifies an ARP request packet contained in the provided buffer to create an
 * ARP reply. It swaps the source and destination MAC and IP addresses, sets the ARP opcode
 * to reply (2), and sends the modified packet out on the specified interface.
 *
 * @param buffer Pointer to the packet buffer containing the ARP request.
 * @param length Length of the packet.
 * @param interface The interface index used for sending the ARP reply.
 */
void arp_reply(char *buffer, int length, int interface) {
    uint8_t mac[MAC_SIZE];
    get_interface_mac(interface, mac);
    // set headers
    struct ether_hdr *ether_header = (struct ether_hdr *) buffer;
    struct arp_hdr *arp_header = (struct arp_hdr *)(buffer + sizeof(struct ether_hdr));
    // swap MACs
    for (int i = 0; i < MAC_SIZE; i++) {
        ether_header->ethr_dhost[i] = ether_header->ethr_shost[i];
        ether_header->ethr_shost[i] = mac[i];
    }

    arp_header->opcode = htons(2);
    // swap IPs
    uint32_t temp_ip = arp_header->sprotoa;
    arp_header->sprotoa = arp_header->tprotoa;
    arp_header->tprotoa = temp_ip;
    // swap ARP MACs
    for (int i = 0; i < MAC_SIZE; i++) {
        arp_header->thwa[i] = arp_header->shwa[i];
        arp_header->shwa[i] = mac[i];
    }
    // send packet
    send_to_link(length, buffer, interface);
}


/**
 * @brief Constructs and sends an ARP request packet.
 *
 * This function builds an ARP request packet to resolve the MAC address of the next hop.
 * It sets the Ethernet header with a broadcast destination and the interface's MAC as the source.
 * The ARP header is filled with the necessary fields for an ARP request and sent out on the given interface.
 *
 * @param route Pointer to the route table entry that contains the next-hop IP address.
 * @param interface Interface index on which to send the ARP request.
 */
void arp_request(struct route_table_entry *route, int interface) {
	char *buf = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	if (!buf) {
		perror("malloc failed for ARP request buffer");
		exit(EXIT_FAILURE);
	}
    // Init Ethernet header
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    // Init ARP header
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    // Set broadcast dest
	hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ethr_dhost);
    // Set source MAC   
    get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(0x0806);

	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = MAC_SIZE;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);

	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));

	memset(arp_hdr->thwa, 0, MAC_SIZE);
	arp_hdr->tprotoa = route->next_hop; // Set target IP from route
    // Send ARP request 
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
	free(buf);
}

/**
 * @brief Processes an ARP reply, updates the ARP table, and sends queued packets.
 *
 * This function extracts the sender's IP and MAC from the received ARP reply, adds it to the ARP table,
 * and then processes each packet in the pending queue that awaits this ARP resolution by updating its
 * Ethernet header and sending it out on the appropriate interface.
 *
 * @param buf Pointer to the buffer containing the ARP reply.
 * @param len Length of the received packet.
 * @param interface The interface index on which the ARP reply was received.
 * @param arp_table Array representing the ARP table.
 * @param arp_table_len Pointer to the current number of entries in the ARP table; it will be incremented.
 * @param pending_queue Queue containing packets waiting for ARP resolution.
 */
void process_arp_reply(char *buf, size_t len, int interface,
                       struct arp_table_entry *arp_table, int *arp_table_len,
                       queue pending_queue) {
    // Init ARP header
    struct arp_hdr *arp_hdr_ptr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    struct arp_table_entry arp_entry;
    arp_entry.ip = arp_hdr_ptr->sprotoa;
    for (int i = 0; i < MAC_SIZE; i++) {
        arp_entry.mac[i] = arp_hdr_ptr->shwa[i];
    }
    // Save ARP entry
    arp_table[(*arp_table_len)] = arp_entry;
    (*arp_table_len)++;
    // Process pending queue
    while (!queue_empty(pending_queue)) {
        void *queued_packet = queue_deq(pending_queue);

        size_t packet_length;
        int output_iface;
        char *packet_data;

        memcpy(&packet_length, queued_packet, sizeof(size_t));
        memcpy(&output_iface, (char *)queued_packet + sizeof(size_t), sizeof(int));
        packet_data = (char *)queued_packet + sizeof(size_t) + sizeof(int);
        
        // Update L2 header
        struct ether_hdr *packet_eth = (struct ether_hdr *)packet_data;
        memcpy(packet_eth->ethr_dhost, arp_hdr_ptr->shwa, MAC_SIZE);

        // Send packet
        send_to_link(packet_length, packet_data, output_iface);
        free(queued_packet);
    }
}

/**
 * @brief Processes a received ARP packet.
 *
 * Distinguishes between ARP requests and replies, handling each appropriately.
 * For an ARP request, it sends an ARP reply; for an ARP reply, it updates the ARP table 
 * and processes any pending packets waiting for this ARP resolution.
 *
 * @param buf Pointer to the buffer containing the ARP packet.
 * @param len Length of the packet.
 * @param interface The interface index on which the packet was received.
 * @param arp_table Array representing the ARP table.
 * @param arp_table_len Pointer to the current number of entries in the ARP table.
 * @param queue_packet Queue holding packets awaiting ARP resolution.
 */
void process_arp_packet(char *buf, size_t len, int interface,
                        struct arp_table_entry *arp_table, int *arp_table_len,
                        queue queue_packet) {
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    switch (ntohs(arp_hdr->opcode)) {
        case 1:
            arp_reply(buf, len, interface);
            break;
        case 2:
            process_arp_reply(buf, len, interface, arp_table, arp_table_len, queue_packet);
            break;
    }
}

/**
 * @brief Processes an incoming IPv4 packet.
 *
 * This function handles IPv4 packets by checking if the packet is for the router,
 * performing checksum and TTL validation, and forwarding the packet based on the routing table.
 * If a matching ARP entry for the next-hop is missing, the packet is queued and an ARP request is sent.
 *
 * @param buf Pointer to the packet buffer.
 * @param len Length of the packet.
 * @param interface Interface index on which the packet was received.
 * @param route_table Pointer to the routing table.
 * @param route_table_length Number of entries in the routing table.
 * @param arp_table Pointer to the ARP table.
 * @param arp_table_len Pointer to the number of ARP entries.
 * @param queue_packet Queue for pending packets awaiting ARP resolution.
 */
void process_ipv4_packet(char *buf, size_t len, int interface,
                         struct route_table_entry *route_table, int route_table_length,
                         struct arp_table_entry *arp_table, int *arp_table_len,
                         queue queue_packet) {

    // Get Ethernet header                        
    struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    // Get IP header
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    // Retrieve interface IP
    char *interface_ip_str = get_interface_ip(interface);
    uint32_t router_ip = inet_addr(interface_ip_str);
    uint8_t *router_mac = calloc(MAC_SIZE, sizeof(uint8_t));
    get_interface_mac(interface, router_mac);
    
    // Packet for router?
    if (ip_hdr->dest_addr == router_ip) {
        char *icmp_buffer = build_icmp_packet(eth_hdr, ip_hdr, router_mac, router_ip, ICMP_ECHO);
        send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
                     icmp_buffer, interface);
        free(icmp_buffer);
        free(router_mac);
        return;
    }
    // Verify checksum
    uint16_t csum = ip_hdr->checksum;
    ip_hdr->checksum = 0;
    uint16_t calculated_checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
    if (csum != calculated_checksum) {
        free(router_mac);
        return;
    }
    // Check TTL
    if (ip_hdr->ttl <= 1) {
        char *icmp_buffer = build_icmp_packet(eth_hdr, ip_hdr, router_mac, router_ip, ICMP_TIME_EXCEEDED);
        send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
                     icmp_buffer, interface);
        free(icmp_buffer);
        free(router_mac);
        return;
    }

    ip_hdr->ttl--;
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

    // Route lookup 
    struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr, route_table_length, route_table);
    if (!best_route) {
        char *icmp_buffer = build_icmp_packet(eth_hdr, ip_hdr, router_mac, router_ip, ICMP_DEST_UNREACH);
        send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
                     icmp_buffer, interface);
        free(icmp_buffer);
        free(router_mac);
        return;
    }
    // ARP lookup
    struct arp_table_entry *arp_entry = NULL;
    for (int i = 0; i < *arp_table_len; i++) {
        if (arp_table[i].ip == best_route->next_hop) {
            arp_entry = &arp_table[i];
            break;
        }
    }
    // Queue if missing ARP
    if (!arp_entry) {
        char *temp_buffer = malloc(len + sizeof(int) + sizeof(size_t));
        memcpy(temp_buffer, &len, sizeof(size_t));
        memcpy(temp_buffer + sizeof(size_t), &best_route->interface, sizeof(int));
        memcpy(temp_buffer + sizeof(size_t) + sizeof(int), buf, len);
        queue_enq(queue_packet, temp_buffer);
        arp_request(best_route, best_route->interface);
        free(router_mac);
        return;
    }

    memcpy(eth_hdr->ethr_dhost, arp_entry->mac, MAC_SIZE);
    get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
    // Forward packet
    send_to_link(len, buf, best_route->interface);
    free(router_mac);
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    init(argv + 2, argc - 2);

    struct route_table_entry *route_table = calloc(80000, sizeof(struct route_table_entry));
    struct arp_table_entry *arp_table = calloc(25, sizeof(struct arp_table_entry));
    int route_table_length = read_rtable(argv[1], route_table);
    int arp_table_length = 0;

    qsort(route_table, route_table_length, sizeof(struct route_table_entry), compare_masks);
    queue queue_packet = create_queue();

    while (1) {
        size_t interface, len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

        if (eth_hdr->ethr_type == htons(0x0806)) {
            process_arp_packet(buf, len, interface, arp_table, &arp_table_length, queue_packet);
            continue;
        }

        if (eth_hdr->ethr_type != htons(ETHERTYPE_IP))
            continue;

        process_ipv4_packet(buf, len, interface, route_table, route_table_length,
                            arp_table, &arp_table_length, queue_packet);
    }

    return 0;
}
