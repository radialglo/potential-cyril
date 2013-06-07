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
#include <stdlib.h>
#include <string.h>
#include <assert.h>


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

void sr_init(struct sr_instance* sr)
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /*
    Since we are being lent the packet let's make a duplicate so that 
    can use it in the scope of different methods
   */
  uint8_t *dup_packet = malloc(len);
  memcpy(dup_packet, packet, len);

  /* EXTRACT ETHERNET HEADER FROM PACKET*/
  sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(dup_packet); 

  /*
    Check destination mac address
    matches the coresponding interface
    at which packet was received
   */

  sr_if_t *iface = sr_get_interface(sr, interface);
  if(memcmp(ether_header->ether_dhost,iface->addr,ETHER_ADDR_LEN) != 0) {
    fprintf(stderr,"Destination mac address %s does not match interface mac address %s\n",
    ether_header->ether_dhost,iface->addr);
    free(dup_packet);
    return;
  }

  /*
    Check type field in the ethernet header
   */
  if(ntohs(ether_header->ether_type) == ethertype_arp) {
    /* If it is an ARP reply,
       do ARP reply proccessing (processing algorithm is in sr_arpcache.h) 
       else it is an ARP request, send an ARP reply
     */

     /* EXTRACT ARP HEADER */
     sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)(packet + ETHER_HDR_LEN);

    if(ntohs(arp_header->ar_op) == arp_op_reply) {

      process_arpreply(sr, arp_header);

    } else {

    /* send arp reply to the ARP requst*/
      send_arpreply(sr, arp_header, interface);
    }

  } else if (ntohs(ether_header->ether_type) == ethertype_ip) {
    /* TODO: Verify checksum, if fail: drop/free the packet*/


    /* TODO:
       Check destination IP
       If destined to the router,
       what is the protcol field in IP header
       ICMP -> ICMP processing (echo request, echo prely)
       UDP,TCP -> ICMP port unreachable
    */

      
    /* TODO:
        If destined to others, lookup gateway address in routing table
        decrease TTL, If TTL = 0; ICMP Time exceeded

        based on returned routing entry:

        if routing entry not found (is NULL) -> ICMP  network unreachable
        queue it up into arp request  queue
        free the passed packet into the queue
     */

    

  }

  free(dup_packet);

}/* end sr_ForwardPacket */

/* type 0 ICMP
   @param packet - includes ethernet headers 
*/
void sendEchoReply(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                   char *interface) {

    sr_if_t *iface = sr_get_interface(sr, interface);

    uint8_t *dup_packet = malloc(len);
    memcpy(dup_packet, packet, len);

    /* PREPARE ETHER HEADER - just switch source and dest */
    sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(dup_packet);

    uint8_t dhost[ETHER_ADDR_LEN];
    strncpy(dhost, ether_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_shost, ether_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_dhost, dhost, ETHER_ADDR_LEN);
    /* the ether_type should be the same */

    /* PREPARE IP HEADER */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(dup_packet + ETHER_HDR_LEN);

    /* Use random id and long ttl */
    ip_header->ip_id = rand() % 10000;
    ip_header->ip_ttl = INIT_TTL;

    /* Flip the source and destination addresses */
    uint32_t ip_src, ip_dst;	/* source and dest address */
    uint32_t new_ip_src = ip_header->ip_dst;
    ip_header->ip_dst = ip_header->ip_src;
    ip_header->ip_src = new_ip_src;

    /* calculate the new checksum for this ip header */
    memset(&(ip_header->ip_sum), 0, sizeof(ip_header->ip_sum));
    uint16_t checksum = cksum(ip_header, IP_HDR_LEN);
    ip_header->ip_sum = checksum;

    /* Prepare the ICMP header */
    /* identifier and sequence numbers are returned the same */
    sr_icmp_t0_hdr_t *icmp_t0 =
        (sr_icmp_t0_hdr_t *)(dup_packet + ETHER_HDR_LEN + IP_HDR_LEN);

    /* Type 0, code 0 */
    icmp_t0->type = 0;
    icmp_t0->code = 0;

    /* validate the checksum */
    checksum = cksum(icmp_t0, sizeof(icmp_t0));
    if ( checksum != 0xFFFF) {
        /* TODO
           What to do here? 
         */
        fprintf(stderr, "Invalid checksum %hu\n", checksum);
        free(dup_packet);
        return;
    }

    sr_send_packet(sr, dup_packet, len, iface->name);
    free(dup_packet);
}
