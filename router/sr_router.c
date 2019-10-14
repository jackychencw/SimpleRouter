/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  uint16_t type = ethertype(packet);
  struct sr_if *sr_interface = sr_get_interface(sr, interface);
  switch (type)
  {
  case ethertype_arp:
    printf("*** -> Received IP packet <- ***\n\n");
    sr_handle_arp(sr,
                  packet,
                  len,
                  sr_interface);
    break;
  case ethertype_ip:
    printf("*** -> Received IP packet <- ***\n\n");
    /* TODO print_hdr_ip(packet);*/
    break;
  default:
    fprintf(stderr, "Invalid ethertype ... droping\n");
    return;
  }
} /* end sr_ForwardPacket */

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *sr_interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = get_ethernet_hdr(packet);
  sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

  if (!arp_sanity_check(len))
  {
    fprintf(stderr, "Packet doesn't meet minimum length requirement.\n");
    return;
  }

  uint16_t op_code = ntohs(arp_hdr->ar_op);

  switch (op_code)
  {
  case arp_op_request:
    /* Handle arp request*/
    printf("Sensed [ARP request], handling ...\n\n");
    sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    break;
  case arp_op_reply:
    /* Handle arp reply*/
    printf("Sensed [ARP reply], handling ...\n\n");
    break;
  default:
    fprintf(stderr, "Invalid packet op code.\n");
    return;
  }
}

void send_arpreq(struct sr_instance *sr,
                   sr_ethernet_hdr_t *ethernet_hdr,
                   sr_arp_hdr_t *arp_hdr,
                   struct sr_if *sr_interface)
{
  int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *rep = (uint8_t *)malloc(packet_size);
}

void send_arprep(struct sr_instance *sr,
                   sr_arp_hdr_t *arp_hder,
                   struct sr_if *rec_iface)
{
  printf("Sr send arp req\n");
}