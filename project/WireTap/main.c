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
#include "util.h"
#define  MAX_ADDRESS 100
#define MAX_PORTS  100

#define DHCP_OP_BOOTREQUEST 1
#define DHCP_OP_BOOTREPLY   2
int there_is_ip = 0;
int there_is_udp = 0;
int there_is_arp = 0;
int there_is_tcp = 0;
int there_is_dcp = 0;
struct timeval start, end;
int min_pkt_size = 999999;
int max_pkt_size = 0;
double avg_pkt_size = 0;
int total_pkt_size = 0;
int pkt_count = 0;
char *eth_unique_address[MAX_ADDRESS];	//array for unique ethernet addresses
int eth_unique_address_count[MAX_ADDRESS];	//count of each unique eth address
int eth_address_count = 0;

char *arp_unique_mac[MAX_ADDRESS];	//array for arp mac
int arp_count = 0;
IPLIST *arp_unique_ip[MAX_ADDRESS];

char *ip_unique_address[MAX_ADDRESS];
int ip_unique_address_count[MAX_ADDRESS];
int ip_address_count = 0;


char *dhcp_clients[MAX_ADDRESS];
int dhcp_clients_packet[MAX_ADDRESS];
int dhcp_clients_count = 0;

char *dhcp_servers[MAX_ADDRESS];
int dhcp_servers_packet[MAX_ADDRESS];
int dhcp_servers_count = 0;

int dhcp_request = 0;
int dhcp_discover = 0;
int dhcp_offer = 0;
int dhcp_ack = 0;

int incorrect_checksum_count = 0;
int correct_checksum_count = 0;
int omit_checksum_count = 0;
u_int16_t udp_scr_unique_ports[MAX_PORTS];
int udp_scr_unique_ports_count[MAX_PORTS];
int udp_scr_ports_count = 0;

u_int16_t udp_dest_unique_ports[MAX_PORTS];
int udp_dest_unique_ports_count[MAX_PORTS];
int udp_dest_ports_count = 0;

u_int16_t tcp_unique_ports[MAX_PORTS];
int tcp_unique_ports_count[MAX_PORTS];
int tcp_ports_count = 0;

void add_eth_address (const char *);
void add_ip_address (const char *);
void add_arp_address (const char *, const char *);
void add_dhcp_client (const char *);
void add_dhcp_server (const char *);
void add_udp_src_port (u_int16_t port);
void add_udp_dest_port (u_int16_t port);
void add_tcp_port (u_int16_t port);

u_int16_t process_ethernet (const u_char *);
u_int8_t process_ip (const u_char *);
void process_tcp (const u_char * packet);
void process_udp (const u_char * packet);
void process_arp (const u_char * packet);
void process_dhcp (const u_char *);
void print_unique_eth_addresses ();
void print_unique_ip_addresses ();
void print_dhcp_clients ();
void print_dhcp_servers ();

/** callback handler for pcap_loop **/
void
processPacket (u_char * arg, const struct pcap_pkthdr *pkt,
	       const u_char * packet)
{
  int *count = (int *) arg;
  u_int16_t protocol;
  (*count)++;

  struct timeval t = pkt->ts;	//hold the time value
  end = t;
  ++pkt_count;
  if (pkt_count == 1)		//start time of capture
    start = t;
  total_pkt_size += pkt->caplen;	//find total packet size
  avg_pkt_size = ((double) total_pkt_size / (double) pkt_count);	//compute avg
  if (min_pkt_size > pkt->caplen)
    {
      min_pkt_size = pkt->caplen;	//find min
    }
  if (max_pkt_size < pkt->caplen)
    {
      max_pkt_size = pkt->caplen;	//find max
    }

  protocol = process_ethernet (packet);	//process the ethernet packet 

  if (ntohs (protocol) == ETHERTYPE_IP)
    {
      u_int8_t ip_protocol = process_ip (packet);

      if (ip_protocol == IPPROTO_TCP)
	{
	  there_is_tcp = 1;
	  process_tcp (packet);
	}
      else if (ip_protocol == IPPROTO_UDP)
	{
	  there_is_udp = 1;
	  process_udp (packet);
	}
    }
  else if (ntohs (protocol) == ETHERTYPE_ARP)
    {
      there_is_arp = 1;
      process_arp (packet);
    }
  return;
}

//method to find the duration of packet capture
static float
timeval_subtract (tv1, tv2)
     struct timeval *tv1, *tv2;
{
  return ((tv1->tv_sec - tv2->tv_sec) +
	  ((float) (tv1->tv_usec - tv2->tv_usec)) / 1000000);
};


/** Process the ethernet packet **/
u_int16_t
process_ethernet (const u_char * packet)
{
  struct ether_header *ethHeader = (struct ether_header *) packet;
  u_int16_t protocol = ethHeader->ether_type;

  char eth_src_addr[20];
  char eth_dst_addr[20];
/*convert the Ethernet host address given in network byte order 
to a string in standard hex-digits-and-colons notation, omitting leading zeroes*/
  sprintf (eth_src_addr, "%s",
	   ether_ntoa ((const struct ether_addr *) &ethHeader->ether_shost));
  sprintf (eth_dst_addr, "%s",
	   ether_ntoa ((const struct ether_addr *) &ethHeader->ether_dhost));
  add_eth_address (eth_dst_addr);	//add addresses to array
  add_eth_address (eth_src_addr);
  return protocol;
}


void
process_arp (const u_char * packet)
{
  struct arp_header *arphdr =
    (struct arp_header *) (packet + sizeof (struct ether_header));
  struct in_addr *sender_ip = (struct in_addr *) arphdr->sender_protoaddr;
  struct in_addr *target_ip = (struct in_addr *) arphdr->target_protoaddr;
//add the arp mac and ip addresses
  add_arp_address ((const char *) ether_ntoa (arphdr->sender_hwaddr),
		   inet_ntoa (*sender_ip));
  add_arp_address ((const char *) ether_ntoa (arphdr->target_hwaddr),
		   inet_ntoa (*target_ip));

}

/** Process the IP header **/
u_int8_t
process_ip (const u_char * packet)
{
  const struct ip *myip =
    (struct ip *) (packet + sizeof (struct ether_header));
//Convert IP addresses from a dots-and-number string to a struct in_addr and back  
  char *src_ip = inet_ntoa (myip->ip_src);
  char *dst_ip = inet_ntoa (myip->ip_dst);
//add ip addresses
  add_ip_address (src_ip);
  add_ip_address (dst_ip);

  return myip->ip_p;
}

/** Process the TCP header **/
void
process_tcp (const u_char * packet)
{
  const struct ip *myip =
    (struct ip *) (packet + sizeof (struct ether_header));
/*IP header, unlike the Ethernet header, does not have a fixed length;
Its length is given, as a count of 4-byte words, by the header length field of the IP header.
As it's a count of 4-byte words, it must be multiplied by 4 to give the size in bytes. 
The minimum length of that header is 20 bytes.  */
  u_int ip_hdr_len = myip->ip_hl * 4;
  struct tcphdr *mytcp =
    (struct tcphdr *) (packet + sizeof (struct ether_header) + ip_hdr_len);
  u_int16_t src_port = mytcp->source;
  u_int16_t dst_port = mytcp->dest;
  add_tcp_port (src_port);
  add_tcp_port (dst_port);
  return;
}

/** Process the UDP header **/
void
process_udp (const u_char * packet)
{
  const struct ip *myip =
    (struct ip *) (packet + sizeof (struct ether_header));
  u_int ip_hdr_len = myip->ip_hl * 4;

  const struct udphdr *myudp =
    (struct udphdr *) (packet + sizeof (struct ether_header) + ip_hdr_len);
  u_int16_t src_port = myudp->source;
  u_int16_t dst_port = myudp->dest;
  //get the original cheksum from packet;
  u_int16_t udpchecksum = (myudp->check);
//find the checksum
  u_int16_t checksum =
    calc_checksum (myudp->len, myip->ip_src.s_addr, myip->ip_dst.s_addr,
		   myudp);
  if (udpchecksum == checksum)
    {
      correct_checksum_count++;	//count correct checksums

    }
  else if (udpchecksum != checksum)
    {
      incorrect_checksum_count++;	//count incorrect checksums
    }
  else
    {
      omit_checksum_count++;

    }

/*DHCP Clients use the port 68 as source port and port 67 as destination port
So if source is 68 and dest is 67,it must be dhcp client.The opposite is true for
DHCP servers.
*/
  if (ntohs (src_port) == 68 && ntohs (dst_port) == 67)
    {
      //dhcp client
      there_is_dcp = 1;
      /*The UDP header has a fixed size of 8 bytes (src port + dest port + length + checksum) 
         after which the data portion starts. The data portion contains the DHCP header and DHCP data. 
         So in order to access the DHCP packet we have to skip 8 bytes from the starting of UDP packet. */

      process_dhcp (packet + sizeof (struct ether_header) + ip_hdr_len + 8);

    }
  else if (ntohs (src_port) == 67 && ntohs (dst_port) == 68)
    {
      // dhcp server
      there_is_dcp = 1;
      process_dhcp (packet + sizeof (struct ether_header) + ip_hdr_len + 8);
    }
  add_udp_scr_port (src_port);
  add_udp_dest_port (dst_port);

  return;
}


void
process_dhcp (const u_char * dhcp_pkt)
{
  struct in_addr c;
  struct in_addr s;
  struct dhcp_header *dhcphdr;

  u_int8_t *tmp = (u_int8_t *) (dhcp_pkt + 236 + 4);
  dhcphdr = (struct dhcp_header *) (dhcp_pkt);

  c.s_addr = dhcphdr->ciaddr;
  s.s_addr = dhcphdr->siaddr;

  add_dhcp_client (inet_ntoa (c));
  add_dhcp_server (inet_ntoa (s));
/*
tmp has been assigned an address to point to the starting of options portion of DHCP packet.
The DHCP packet has a fixed header size of 236 bytes that includes all fields upto 
"file name" after which the data portion starts. Now the first 4 bytes of data 
has some fixed values after which DHCP option starts.
The first byte of options is Tag field and then Length field(variable as per Tag value)
and then the option value as per Tag value. 
Now if the Tag value is 53 which is for message type then length is 1 (1 byte) 
and so we need to skip 2 bytes to reach the option value. 
The possible option values for a Tag value of 53 are as below:	
*/

  if (*tmp == 53)
    {
      u_int8_t *value = (u_int8_t *) ((tmp + 2));
      switch (*value)
	{
	case DHCPDISCOVER:
	  dhcp_discover++;
	  break;
	case DHCPOFFER:
	  dhcp_offer++;
	  break;
	case DHCPREQUEST:

	  dhcp_request++;
	  break;
	case DHCPDECLINE:

	  break;
	case DHCPACK:

	  dhcp_ack++;
	  break;
	case DHCPNAK:
	  break;
	case DHCPRELEASE:
	  break;
	case DHCPINFORM:
	  break;
	default:
	  break;

	}
    }

}

/** Adds an ethernet address to the list if its unique **/
void
add_eth_address (const char *addr)
{
  int i;
  int unique = 1;
  for (i = 0; i < eth_address_count; i++)
    {
      if (strcmp (addr, eth_unique_address[i]) == 0)
	{
	  eth_unique_address_count[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      eth_unique_address[eth_address_count] = (char *) malloc (sizeof (char) * 20);	//allocate some some memory 
      strcpy (eth_unique_address[eth_address_count], addr);
      eth_unique_address_count[eth_address_count] = 1;
      eth_address_count++;
    }

}

/** Adds an ARP participant **/
void
add_arp_address (const char *mac, const char *ip)
{
  int i;
  IPLIST *tmp, *prev;
  int unique = 1, found = 0;

  for (i = 0; i < arp_count; i++)
    {
      if (strcmp (mac, arp_unique_mac[i]) == 0)
	{
	  tmp = arp_unique_ip[i];
	  while (tmp != NULL)
	    {
	      prev = tmp;
	      if (strcmp (tmp->ip, ip) == 0)
		{
		  found = 1;
		  break;
		}
	      tmp = (tmp->next);
	    }
	  if (!found)
	    {
	      prev->next = (IPLIST *) malloc (sizeof (IPLIST));
	      strcpy ((prev->next)->ip, ip);
	      (prev->next)->next = NULL;
	    }
	  unique = 0;
	  break;
	}
    }

  if (unique)
    {
      arp_unique_mac[arp_count] = (char *) malloc (sizeof (char) * 20);
      strcpy (arp_unique_mac[arp_count], mac);
      arp_unique_ip[arp_count] = (IPLIST *) malloc (sizeof (IPLIST));
      strcpy (arp_unique_ip[arp_count]->ip, ip);
      arp_unique_ip[arp_count]->next = NULL;
      arp_count++;
    }

}

/** Adds an IP address to the list if its unique **/
void
add_ip_address (const char *addr)
{
  int i;
  int unique = 1;
  for (i = 0; i < ip_address_count; i++)
    {
      if (strcmp (addr, ip_unique_address[i]) == 0)
	{
	  ip_unique_address_count[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      ip_unique_address[ip_address_count] =
	(char *) malloc (sizeof (char) * 20);
      strcpy (ip_unique_address[ip_address_count], addr);
      ip_unique_address_count[ip_address_count]++;
      ip_address_count++;
    }

}


/** Adds a DHCP client if its unique **/
void
add_dhcp_client (const char *addr)
{
  int i;
  int unique = 1;
  for (i = 0; i < dhcp_clients_count; i++)
    {
      if (strcmp (addr, dhcp_clients[i]) == 0)
	{
	  dhcp_clients_packet[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      dhcp_clients[dhcp_clients_count] = (char *) malloc (sizeof (char) * 20);
      strcpy (dhcp_clients[dhcp_clients_count], addr);
      dhcp_clients_packet[dhcp_clients_count] = 1;
      dhcp_clients_count++;
    }

}

/** Adds a DHCP server if its unique **/
void
add_dhcp_server (const char *addr)
{
  int i;
  int unique = 1;
  for (i = 0; i < dhcp_servers_count; i++)
    {
      if (strcmp (addr, dhcp_servers[i]) == 0)
	{
	  dhcp_servers_packet[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      dhcp_servers[dhcp_servers_count] = (char *) malloc (sizeof (char) * 20);
      strcpy (dhcp_servers[dhcp_servers_count], addr);
      dhcp_servers_packet[dhcp_servers_count] = 1;
      dhcp_servers_count++;
    }

}


void
add_udp_scr_port (u_int16_t port)
{
  int i;
  int unique = 1;
  for (i = 0; i < udp_scr_ports_count; i++)
    {
      if (port == udp_scr_unique_ports[i])
	{
	  udp_scr_unique_ports_count[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      udp_scr_unique_ports[udp_scr_ports_count] = port;
      udp_scr_unique_ports_count[udp_scr_ports_count]++;
      udp_scr_ports_count++;
    }

}

void
add_udp_dest_port (u_int16_t port)
{
  int i;
  int unique = 1;
  for (i = 0; i < udp_dest_ports_count; i++)
    {
      if (port == udp_dest_unique_ports[i])
	{
	  udp_dest_unique_ports_count[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      udp_dest_unique_ports[udp_dest_ports_count] = port;
      udp_dest_unique_ports_count[udp_dest_ports_count]++;
      udp_dest_ports_count++;
    }

}

void
add_tcp_port (u_int16_t port)
{
  int i;
  int unique = 1;
  for (i = 0; i < tcp_ports_count; i++)
    {
      if (port == tcp_unique_ports[i])
	{
	  tcp_unique_ports_count[i]++;
	  unique = 0;
	  break;
	}
    }
  if (unique)
    {
      tcp_unique_ports[tcp_ports_count] = port;
      tcp_unique_ports_count[tcp_ports_count]++;
      tcp_ports_count++;
    }

}




void
print_unique_eth_addresses ()
{
  int i;
  for (i = 0; i < eth_address_count; i++)
    {
      printf ("%s (%d) \n", eth_unique_address[i],
	      eth_unique_address_count[i]);
    }
}

void
print_unique_ip_addresses ()
{
  int i;
  for (i = 0; i < ip_address_count; i++)
    {
      printf ("%s (%d) \n", ip_unique_address[i], ip_unique_address_count[i]);
    }
}

void
print_arp_participants ()
{
  int i;
  IPLIST *tmp;
  for (i = 0; i < arp_count; i++)
    {
      printf ("MAC Address: %s Associated IP Addresses ->\n",
	      arp_unique_mac[i]);

      for (tmp = arp_unique_ip[i]; tmp != NULL; tmp = (tmp->next))
	{
	  printf ("%s,", tmp->ip);
	}
      printf ("\n\n");
    }
}


void
print_dhcp_clients ()
{
  int i;
  for (i = 0; i < dhcp_clients_count; i++)
    {
      printf ("%s (%d) \n", dhcp_clients[i], dhcp_clients_packet[i]);
    }
}

void
print_dhcp_servers ()
{
  int i;
  for (i = 0; i < dhcp_servers_count; i++)
    {
      printf ("%s (%d) \n", dhcp_servers[i], dhcp_servers_packet[i]);
    }
}


void
print_unique_udp_ports ()
{
  printf ("\nUnique UDP Source Ports\n");
  printf ("-----------------------------\n");
  int i, j;
  for (i = 0; i < udp_scr_ports_count; i++)
    {
      printf ("%d\n", ntohs (udp_scr_unique_ports[i]));
    }
  printf ("\nUnique UDP Destination Ports\n");
  printf ("-----------------------------\n");
  for (j = 0; j < udp_dest_ports_count; j++)
    {
      printf ("%d\n", ntohs (udp_dest_unique_ports[j]));
    }
	printf("\n");
}

void
print_unique_tcp_ports ()
{
  int i;
  for (i = 0; i < tcp_ports_count; i++)
    {
      printf ("%d\n", ntohs (tcp_unique_ports[i]));
    }
}

int
main (int argc, char *argv[])
{

  pcap_t *ethdescr = NULL;
  char errbuff[PCAP_ERRBUF_SIZE];
  if (argc < 2)
    {
      printf ("\nUsage: ./wiretap  <TCPDUM_FILE>\n\n");
      exit (0);
    }
  const char *fname = argv[1];
  int count = 0;

  ethdescr = pcap_open_offline (fname, errbuff);
  if (ethdescr == NULL)
    {
      printf ("\nERROR: pcap failed to open the saved file %s\n", fname);
      exit (0);
    }
  if (pcap_datalink (ethdescr) != DLT_EN10MB)
    {
      printf
	("ERROR: tcpdump file does not contain ethernet packets..aborting\n");
      exit (0);
    }

  printf ("\n\n");
  pcap_loop (ethdescr, -1, processPacket, (u_char *) & count);
  printf ("***********************************\n");
  printf ("*    Packet Capture Statistics    *\n");
  printf ("*                                 *\n");
  printf ("***********************************\n");
  printf ("\nStart Time of packet capture : %s\n", ctime (&start));
  printf ("Duration of packet capture: %f \n",
	  timeval_subtract (&end, &start));
  printf ("Total Packets : %d\n", count);
  printf ("Avg Packet Size : %.2f\n", avg_pkt_size);
  printf ("Min Packet Size : %d\n", min_pkt_size);
  printf ("Max Packet Size : %d\n", max_pkt_size);
	printf("-------------------------------------------\n");
  printf ("\nUnique Ethernet addresses (Packet Count) : \n");
  print_unique_eth_addresses ();
	printf("-------------------------------------------\n");
  printf ("\nUnique IP addresses (Packet Count) : \n");
	printf("--------------------------------------\n");
  print_unique_ip_addresses ();
	printf("--------------------------------------\n");
  if (there_is_arp == 1)
    {
      printf ("\nUnique ARP Participants : \n");
		printf("-------------------------\n");
      print_arp_participants ();
		printf("-------------------------\n");
    }
  if (there_is_udp == 1)
    {
	  print_unique_udp_ports ();
		printf("--------------------------------------------\n");
      printf ("\nNumber of Packets With Correct Checksum: %d\n",
	      correct_checksum_count);
      printf ("Number of Packets With Incorrect Checksum: %d\n",
	      incorrect_checksum_count);
      printf ("Number of Packets Omit Checksum: %d\n", omit_checksum_count);
		printf("---------------------------------------------\n");
    }
  if (there_is_tcp == 1)
    {
      printf ("\nUnique TCP Ports : \n");
	  printf("----------------------\n");
      print_unique_tcp_ports ();
		printf("--------------------\n");

    }
  if (there_is_dcp == 1)
    {
      printf ("\nDHCP clients (Packet Count) :\n");
		printf("-------------------------\n");
      print_dhcp_clients ();
      printf ("\nDHCP servers (Packet Count)  :\n");
		printf("-------------------------\n");
      print_dhcp_servers ();
      printf ("\nNo of DHCPREQUEST packets : %d\n", dhcp_request);
      printf ("No of DHCPOFFER packets : %d \n", dhcp_offer);
      printf ("No of DHCPDISCOVER packets : %d\n", dhcp_discover);
      printf ("No of DHCPACK packets : %d\n\n", dhcp_ack);
		printf("-------------------------\n");
    }
  pcap_close (ethdescr);
  return 0;
}
