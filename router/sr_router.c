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
    printf("This is an arp packet\n");
    sr_handle_arp(sr,
                  packet,
                  len,
                  sr_interface);
    break;
  case ethertype_ip:
    printf("This is an ip packet\n");
    /* TODO print_hdr_ip(packet);*/
    break;
  default:
    fprintf(stderr, "not IP or ARP\n");
    return;
  }
} /* end sr_ForwardPacket */

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *sr_interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = get_ethernet_hdr(packet);
  print_hdr_eth(packet);
  sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
  print_hdr_arp(packet);
  if (!arp_sanity_check(len))
  {
    fprintf(stderr, "Packet doesn't meet minimum length requirement.\n");
    return;
  }

  uint16_t op_code = ntohs(arp_hdr->ar_op);
  printf("%u\n", (unsigned int)op_code);
  Debug("Sensed an ARP frame, processing it\n");
  switch (op_code)
  {
  case arp_op_request:
    /* Handle arp request*/
    handle_arpreq(sr, ethernet_hdr, arp_hdr, sr_interface);
    break;
  case arp_op_reply:
    /* Handle arp reply*/
    handle_arprep(sr, arp_hdr, sr_interface);
    break;
  default:
    fprintf(stderr, "Wrong packet op code.\n");
    return;
  }
}

/* Handle arp request, if is request, construct reply and send it back */
void handle_arpreq(struct sr_instance *sr,
                   sr_ethernet_hdr_t *eth_hdr,
                   sr_arp_hdr_t *arp_hdr,
                   struct sr_if *sr_if)
{
  /* sr_arpcache_insert((&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip); */
  printf("Simple router sending arp request.\n");
  /* sr_send_arp_rep(sr, eth_hdr, arp_hdr, sr_if); */
}

void sr_send_arp_rep(struct sr_instance *sr,
                     sr_ethernet_hdr_t *eth_hdr,
                     sr_arp_hdr_t *arp_hdr,
                     struct sr_if *sr_if)
{
  /* int packet_size = sizeof(eth_hdr) + sizeof(arp_hdr); */
  printf("Simple router sending arp reply.\n");
  /* uint8_t *packet = (uint8_t *)malloc(packet_size); */
}

/* Handle arp reply, if is reply, save to cache and sendout request */
void handle_arprep(struct sr_instance *sr,
                   sr_arp_hdr_t *arp_hder,
                   struct sr_if *rec_iface)
{
  printf("Simple router sending arp request.\n");
}

void sr_send_arp_req(struct sr_instance *sr,
                     sr_arp_hdr_t *arp_hder,
                     struct sr_if *rec_iface)
{
  printf("Sr send arp req\n");
}