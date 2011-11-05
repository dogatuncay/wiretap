#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8
/*
 * DHCP header
 */

struct dhcp_header
{
  u_int8_t op;
  u_int8_t htype;
  u_int8_t hlen;
  u_int8_t hops;
  u_int32_t xid;
  u_int16_t secs;
  u_int16_t flags;
  u_int32_t ciaddr;
  u_int32_t yiaddr;
  u_int32_t siaddr;
  u_int32_t giaddr;
  char chaddr[16];
  char sname[64];
  char file[128];
};

/*
 * Ethernet ARP format
 */

struct arp_header
{
  unsigned short int ar_hrd;	/* Format of hardware address.  */
  unsigned short int ar_pro;	/* Format of protocol address.  */
  unsigned char ar_hln;		/* Length of hardware address.  */
  unsigned char ar_pln;		/* Length of protocol address.  */
  unsigned short int ar_op;	/* ARP opcode (command).  */

  u_int8_t sender_hwaddr[6];	/* sender hardware address */
  u_int8_t sender_protoaddr[4];	/* sender protocol address */
  u_int8_t target_hwaddr[6];	/* target hardware address */
  u_int8_t target_protoaddr[4];	/* target protocol address */
};

typedef struct ip_list
{
  char ip[20];
  struct ip_list *next;
} IPLIST;



u_int16_t
calc_checksum (u_int16_t len_udp, in_addr_t src_addr, in_addr_t dest_addr,
	       const void *pktbuff)
{
  u_int16_t prot_udp = 17;
  u_int16_t padd = 0;
  u_int32_t sum;
  int i;
  uint16_t *ip_src = (void *) &src_addr, *ip_dst = (void *) &dest_addr;
  uint16_t *buff = (u_int16_t *) pktbuff;
  u_int16_t length_udp = ntohs (len_udp);
  // Find out if the length of data is even or odd number. If odd,
  // add a padding byte = 0 at the end of packet

//      printf("\n Length of UDP = %#x  %d      ntohs %#x  %d\n",len_udp,len_udp,(length_udp),(length_udp));
  if (length_udp & 1)
    {
      padd = 1;
      *(buff + (length_udp / 2)) = 0;	// Add the padding if the packet length is odd
    }

  *(buff + 3) = 0;		// set the checksum field to zero in the buff, this will enable you to get the checksum back
  //initialize sum to zero
  sum = 0;

  // make 16 bit words out of every two adjacent 8 bit words and 
  // calculate the sum of all 16 bit words
  for (i = 0; i < (length_udp + padd) / 2; i++)
    {
      sum = sum + buff[i];
    }

  sum += *(ip_src++);
  sum += *(ip_src);

  sum += *(ip_dst++);
  sum += *(ip_dst);


  // The Protocol number and the length of the UDP packet. 
  // Protocol is in host byte order so we have to change it to network byte order before sum
  sum = sum + htons (prot_udp) + len_udp;

  // keep only the last 16 bits of the 32 bit calculated sum and add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  // Take the one's complement of sum
  sum = ~sum;

  return ((u_int16_t) sum);
}
