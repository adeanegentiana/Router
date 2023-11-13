#include "include/queue.h"
#include "include/skel.h"

#define MACSIZE 6
#define ARPTBSIZE 10
#define IPSTRSIZE 20
#define RTBLESIZE 70000

struct route_table_entry {
	uint32_t prefix;
	uint32_t nextHop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[MACSIZE];
};

// parsez tabela si returnez dimensiunea ei
int parseRoutingTable(struct route_table_entry *routingTable, char *fileName) {
	FILE *f;
	f = fopen(fileName, "r");

	int routingTableSize = 0;
	char *prefix, *nextHop, *mask;
	prefix = (char *)calloc(IPSTRSIZE, sizeof(char));
	nextHop = (char *)calloc(IPSTRSIZE, sizeof(char));
	mask = (char *)calloc(IPSTRSIZE, sizeof(char));
	int interface;
	while (fscanf(f, "%s %s %s %d", prefix, nextHop, mask, &interface) != EOF)
 {
		routingTable[routingTableSize].prefix = inet_addr(prefix);
		routingTable[routingTableSize].nextHop = inet_addr(nextHop);
		routingTable[routingTableSize].mask = inet_addr(mask);
		routingTable[routingTableSize].interface = interface;
		routingTableSize++;
	}
	return routingTableSize;
}

int compare (const void *e1, const void *e2) {
	struct route_table_entry *eAux1 = (struct route_table_entry *)e1;
	struct route_table_entry *eAux2 = (struct route_table_entry *)e2;
	return (eAux1->prefix - eAux2->prefix);
}

int findBestRoute (struct route_table_entry *routingTable, uint32_t dest, int l, int r) {
	int mid = (l + r) / 2;
	while (l <= r) {
		if ((dest & routingTable[mid].mask) == routingTable[mid].prefix)
			return mid;
		else if ((dest & routingTable[mid].mask) > routingTable[mid].prefix)
			return findBestRoute(routingTable, dest, mid + 1, r);
		else 
			return findBestRoute(routingTable, dest, l, mid - 1);
	}
	return -1;
}

struct arp_entry *getArpEntry (uint32_t ip, struct arp_entry *arpTable, int arpTableSize) {
	int i;
	for (i = 0; i < arpTableSize; i++) {
		if (ip == arpTable[i].ip) 
			return &arpTable[i];
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	init(argc - 2, argv + 2);

	struct route_table_entry *routingTable = calloc(RTBLESIZE, sizeof(struct route_table_entry));
	DIE(routingTable == NULL, "memory");
	int routingTableSize = parseRoutingTable(routingTable, argv[1]);
	qsort(routingTable, routingTableSize, sizeof(struct route_table_entry), compare);

	struct arp_entry *arpTable = calloc(ARPTBSIZE, sizeof(struct arp_entry));
	int arpTableSize = 0;

	packet m;
	int rc;

	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// extrag headerul ethernet ca sa verific daca pachetul este IP sau ARP
		struct ether_header *ethHdr = (struct ether_header *)m.payload;
		if (ethHdr->ether_type == ntohs(ETHERTYPE_IP)) {
			struct iphdr *ipHdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			struct icmphdr *icmpHdr = parse_icmp(m.payload);
			if (ntohl(ipHdr->daddr) == inet_network(get_interface_ip(m.interface))) { // daca pachetul este pentru router
				if (icmpHdr->type == ICMP_ECHO) { // trimit icmp echo reply daca primesc icmp echo request
					send_icmp(ipHdr->saddr, ipHdr->daddr, ethHdr->ether_dhost,
							  ethHdr->ether_shost, ICMP_ECHOREPLY, 0,
							  m.interface, icmpHdr->un.echo.id,
							  icmpHdr->un.echo.sequence);
					continue;
				}
			}

			if (ip_checksum(ipHdr, sizeof(struct iphdr)) != 0) {
				// daca checksumul este gresit, dropez pachetul
				continue;
			}

			if (ipHdr->ttl <= 1) {
				send_icmp_error(ipHdr->saddr, ipHdr->daddr, ethHdr->ether_dhost,
								ethHdr->ether_shost, ICMP_TIME_EXCEEDED, 0,
								m.interface);
				continue;
			}

			int bestRoute = findBestRoute(routingTable, ipHdr->daddr, 0, routingTableSize);
			if (bestRoute == -1) {
				send_icmp_error(ipHdr->saddr, ipHdr->daddr, ethHdr->ether_dhost,
								ethHdr->ether_shost, ICMP_DEST_UNREACH, 0,
								m.interface);
				continue;
			}

			ipHdr->ttl--;
			ipHdr->check = 0;
			ipHdr->check = ip_checksum(ipHdr, sizeof(struct iphdr));

			struct arp_entry *arpEntry = getArpEntry(routingTable[bestRoute].nextHop, arpTable, arpTableSize);
			if (!arpEntry) {
				// copiez pachetul si-l bag in coada
				packet *mCopy = calloc(1, sizeof(packet));
				memcpy(mCopy, &m, sizeof(m));
				queue_enq(q, mCopy);
				get_interface_mac(routingTable[bestRoute].interface, ethHdr->ether_shost);
				memset(ethHdr->ether_dhost, 0xff, MACSIZE); // pentru a trimite cerere arp broadcast (ff:ff:ff:ff:ff:ff)
				ethHdr->ether_type = ntohs(ETHERTYPE_ARP);
				send_arp(routingTable[bestRoute].nextHop,
						 inet_addr(get_interface_ip(routingTable[bestRoute].interface)),
						 ethHdr, routingTable[bestRoute].interface,
						 htons(ARPOP_REQUEST));
				continue;
			}

			// destinatia pachetului va fi cea gasita in tabela arp
			memcpy(ethHdr->ether_dhost, arpEntry->mac, sizeof(arpEntry->mac));

			send_packet(routingTable[bestRoute].interface, &m);
		}
		else {
			struct arp_header *arpHdr = parse_arp(m.payload);
			if (arpHdr->op == htons(ARPOP_REQUEST)) {
				// trimit adresa mea catre sursa
				get_interface_mac(m.interface, ethHdr->ether_shost);
				memcpy(ethHdr->ether_dhost, arpHdr->sha, sizeof(arpHdr->sha));
				send_arp(arpHdr->spa, arpHdr->tpa, ethHdr, m.interface, htons(ARPOP_REPLY));
				continue;
			}
			else if (arpHdr->op == htons(ARPOP_REPLY)) {
				// updatez tabela arp
				arpTable[arpTableSize].ip = arpHdr->spa;
				memcpy(arpTable[arpTableSize].mac, arpHdr->sha, MACSIZE);
				// si trimit pachet din coada
				if (!queue_empty(q)) {
					packet *packQ = (packet *)queue_deq(q);
					struct ether_header *ethHdr = (struct ether_header *)packQ->payload;
					struct iphdr *ipHdr = (struct iphdr *)(packQ->payload + sizeof(struct ether_header));
					int bestRoute = findBestRoute(routingTable, ipHdr->daddr, 0, routingTableSize);
					memcpy(ethHdr->ether_dhost, arpTable[arpTableSize].mac, MACSIZE);
					send_packet(routingTable[bestRoute].interface, packQ);
				}
				arpTableSize++;
			}
		}
	}
}