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


int sr_send_arprep(struct sr_instance *sr,
sr_ethernet_hdr_t *origin_ethernet_hder,
                   sr_arp_hdr_t *origin_arp_hder,
                   struct sr_if *received_interface)
{
  printf("Sr send arp req\n");
  unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(packet_size);

  /* First assign pointer to ethernet header, then arp header */
  sr_ethernet_hdr_t *reply_ethernet_hder = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t *reply_arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  memcpy(reply_ethernet_hder->ether_dhost, origin_ethernet_hder->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethernet_hder->ether_shost, received_interface->addr, ETHER_ADDR_LEN);
  reply_ethernet_hder->ether_type = ntohs(ethertype_arp);

  reply_arp_hder->ar_hrd = origin_arp_hder->ar_hrd;
  reply_arp_hder->ar_pro = origin_arp_hder->ar_pro;
  reply_arp_hder->ar_hln = origin_arp_hder->ar_hln;
  reply_arp_hder->ar_pln = origin_arp_hder->ar_pln;
  reply_arp_hder->ar_op = htons(arp_op_reply);
  memcpy(reply_arp_hder->ar_sha, received_interface->addr, ETHER_ADDR_LEN);
  reply_arp_hder->ar_sip = received_interface->ip;
  memcpy(reply_arp_hder->ar_tha, origin_arp_hder->ar_tha, ETHER_ADDR_LEN);
  reply_arp_hder->ar_tip = origin_arp_hder->ar_sip;

  int res = sr_send_packet(sr, packet, packet_size, received_interface->name);
  return res;
}

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
    /* TODO: handle arp op request. */
    break;
  case arp_op_reply:
    /* Handle arp reply*/
    printf("Sensed [ARP reply], handling ...\n\n");
    /* TODO: handle arp op reply. */
    break;
  default:
    fprintf(stderr, "Invalid packet op code.\n");
    return;
  }
}

int sr_send_arpreq(struct sr_instance *sr, uint32_t destination)
{
  unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(packet_size);
  
  /* First assign pointer to ethernet header, then arp header */
  sr_ethernet_hdr_t *ethernet_hder = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t *arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* TODO: Find interface for destination 
  struct sr_if *sr_interface;

  memset(ethernet_hder->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(ethernet_hder->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);*/
  return 1;

}

struct sr_if* sr_get_if_for_dhost(struct sr_instance *sr, uint32_t destination){
  /*TODO*/
}

