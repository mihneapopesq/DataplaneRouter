#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

// ok 
struct route_table_entry *get_best_route(struct route_table_entry* rtable, uint32_t ip_dest, int rtable_len) {
    
	int start = 0, end = rtable_len - 1;
	struct route_table_entry *match = NULL;

	while (start <= end) {
		int pivot = start + (end - start) / 2;

		uint32_t prefix = rtable[pivot].prefix;
		uint32_t mask = rtable[pivot].mask;
		uint32_t masked_ip = ip_dest & mask;

		if (masked_ip == prefix) {
			match = &rtable[pivot];
			start = pivot + 1; 
		} else {
			if (ntohl(masked_ip) < ntohl(prefix)) {
				end = pivot - 1;
			} else {
				start = pivot + 1;
			}
		}
	}

	return match;
}

// ok 
struct arp_table_entry *get_mac_entry(struct arp_table_entry* mac_table, uint32_t given_ip, int mac_table_len) {
    int i = 0;

    while (i < mac_table_len) {
        if (mac_table[i].ip == given_ip) {
            return &mac_table[i];
        }
		i++;
    }

    return NULL;
}

// ok
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


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	struct route_table_entry *route_table = NULL;
	struct arp_table_entry *arp_table = NULL;
	int route_table_length, arp_table_length;

	route_table = calloc(80000, sizeof(struct route_table_entry));
	arp_table = calloc(25, sizeof(struct arp_table_entry));
	route_table_length = read_rtable(argv[1], route_table);
	arp_table_length = parse_arp_table("arp_table.txt", arp_table);

	qsort(route_table, route_table_length, sizeof(struct route_table_entry), compare_masks);


	// pana aici e totul ok problema e in while 

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// Parsare header Ethernet
		void *frame_ptr = (void *)buf;
		struct ether_hdr *eth_hdr = (struct ether_hdr *)frame_ptr;

		// Parsare header IP (offset după Ethernet)
		struct ip_hdr *ip_header = (struct ip_hdr *)((char *)frame_ptr + sizeof(struct ether_hdr));

		// Obținere IP router pentru interfață curentă
		char *interface_ip_str = get_interface_ip(interface);
		uint32_t router_ip = inet_addr(interface_ip_str);

		// Alocare și inițializare MAC router
		uint8_t *router_mac = calloc(6, sizeof(uint8_t));
		get_interface_mac(interface, router_mac);



		// verifcarea ip ului cu checksum
		// ori asa ori != 0
		uint16_t csum = ip_header->checksum;
		ip_header->checksum = 0;
		uint16_t calculated_checksum = ntohs(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

		
		if (csum != calculated_checksum) {
			// checksum failed
			continue;
		}

		// verficiarea TTL ului

		if(ip_header->ttl <= 1) {
			continue;
		} else {
			ip_header->ttl--;	
		}

		uint16_t *raw_header = (uint16_t *)ip_header;

		
		ip_header->checksum = htons(checksum(raw_header, sizeof(struct ip_hdr)));
		

		//caut cea mai buna ruta
		struct route_table_entry *best_route = get_best_route(route_table, ip_header->dest_addr, route_table_length);
		if (best_route == NULL) {
			continue;
		}

		//update adresa sursa si cautarea adresei MAC a interfetei
		struct arp_table_entry *arp_entry = get_mac_entry(arp_table, ip_header->dest_addr, arp_table_length);
		if(arp_entry == NULL) {
			continue;
		}
		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
		get_interface_mac(interface, eth_hdr->ethr_shost);
		send_to_link(len, buf, best_route->interface);


    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

