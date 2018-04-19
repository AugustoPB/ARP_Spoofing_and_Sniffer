#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "arp.h"

unsigned char my_mac[6];
unsigned char my_ip[4];
unsigned char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char dst_mac[6] =	{0xa4, 0x1f, 0x72, 0xf5, 0x90, 0xa8};
unsigned char src_mac[6] =	{0xb8, 0xca, 0x3a, 0xfe, 0x4f, 0x8e};
unsigned char atc_mac[6] = {0xa4,0x1f,0x72,0xf5,0x90,0x59};
unsigned char src_ip[4] = {10,32,143,223};
unsigned char dst_ip[4] = {10,32,143,215};
unsigned char atc_ip[4] = {10,32,143,152};

union eth_buffer fill_arp(unsigned char srcIP[4], unsigned char srcMAC[6],
													unsigned char dstIP[4], unsigned char dstMAC[6],
													int operation)
{
	union eth_buffer buffer_u;

	/* fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dstMAC, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, srcMAC, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

	/* fill payload data (incomplete ARP request example) */
	buffer_u.cooked_data.payload.arp.hw_type = htons(1);
	buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);
	buffer_u.cooked_data.payload.arp.hlen = 6;
	buffer_u.cooked_data.payload.arp.plen = 4;
	buffer_u.cooked_data.payload.arp.operation = htons(operation);
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, srcMAC, 6);
	//memset(buffer_u.cooked_data.payload.arp.src_paddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, srcIP, 4);
	//memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_hwaddr, dstMAC, 6);
	//memset(buffer_u.cooked_data.payload.arp.tgt_paddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, dstIP, 4);

	return buffer_u;
}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts, if_addr;
	struct sockaddr_in pc1_addr, pc2_addr;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;

	char pc1_ip_string[16], pc2_ip_string[16];
	unsigned char pc1_ip[4], pc2_ip[4];
	unsigned char pc1_mac[6], pc2_mac[6];

	union eth_buffer buffer_u;

	/* Get interface name */
	if (argc == 4)
	{
		strcpy(ifName, argv[1]);
		strcpy(pc1_ip_string, argv[2]);
		strcpy(pc2_ip_string, argv[3]);
	}
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(my_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* Get the IP address of the interface */
	if_addr.ifr_addr.sa_family = AF_INET;
	strncpy(if_addr.ifr_name, ifName, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &if_addr) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(my_ip, if_addr.ifr_addr.sa_data+2, 4);

	printf("My MAC: %x:%x%x:%x:%x:%x\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

	printf("My IP: %d.%d.%d.%d\n",my_ip[0],my_ip[1],my_ip[2],my_ip[3]);

	/* Get the MAC address of the computer 1 */

	pc1_addr.sin_family = AF_INET;
	if (inet_aton(pc1_ip_string, &pc1_addr.sin_addr) == 0)
	{
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
  }
	//unsigned char test[4];
	memcpy(pc1_ip, &pc1_addr.sin_addr.s_addr, 4);
	//test = inet_ntoa(pc1_addr.sin_addr);

	printf("PC1 IP: %d.%d.%d.%d\n",pc1_ip[0],pc1_ip[1],pc1_ip[2],pc1_ip[3]);

		/* ARP Request to get MAC of the computer 1*/
	buffer_u = fill_arp(my_ip, my_mac, pc1_ip, bcast_mac, 1);

	memcpy(socket_address.sll_addr, bcast_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

	while (1)
	{
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL); //(struct sockaddr*)&pc1_addr
		printf("packet size: %d\n", numbytes);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP) && buffer_u.cooked_data.payload.arp.operation == ARP_REPLY)
		{
			memcpy(pc1_mac, buffer_u.cooked_data.payload.arp.src_hwaddr, 6);
			break;
		}
	}

		printf("PC1 MAC: %x:%x%x:%x:%x:%x\n", pc1_mac[0],pc1_mac[1],pc1_mac[2],pc1_mac[3],pc1_mac[4],pc1_mac[5]);

	/* Get the MAC address of the computer 2 */


	/* End of configuration. Now we can send and receive data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */

	buffer_u = fill_arp(atc_ip, my_mac, dst_ip, dst_mac, 2);

	/* Send it.. */
	printf("sendind\n");
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	/* To receive data (in this case we will inspect ARP and IP packets)... */

	while (1){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
			printf("ARP packet, %d bytes - operation %d\n", numbytes, ntohs(buffer_u.cooked_data.payload.arp.operation));
			//printf("ARP packet srcIP: %s dstIP: %s srcMAC: %s dstMAC: %s\n", buffer_u.cooked_data.payload.arp.src_paddr, buffer_u.cooked_data.payload.arp.src_hwaddr,
		//buffer_u.cooked_data.payload.arp.tgt_paddr, buffer_u.cooked_data.payload.arp.tgt_hwaddr);
		printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
			numbytes,
			buffer_u.cooked_data.payload.arp.src_paddr[0], buffer_u.cooked_data.payload.arp.src_paddr[1],
			buffer_u.cooked_data.payload.arp.src_paddr[2], buffer_u.cooked_data.payload.arp.src_paddr[3],
			buffer_u.cooked_data.payload.arp.tgt_paddr[0], buffer_u.cooked_data.payload.arp.tgt_paddr[1],
			buffer_u.cooked_data.payload.arp.tgt_paddr[2], buffer_u.cooked_data.payload.arp.tgt_paddr[3],
			buffer_u.cooked_data.payload.ip.proto
		);
			continue;
		}

		printf("got a packet, %d bytes\n", numbytes);
	}

	return 0;
}
