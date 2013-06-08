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
        uint8_t *packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /* SANITY CHECK FOR LENGTH*/
  if (len < ETHER_HDR_LEN) {
    fprintf(stderr , "** Error: Recieved packet is way to short \n");
    return;
  }

  /*
    Since we are being lent the packet let's make a duplicate so that
    can use it in the scope of different methods
   */
  uint8_t *buffer = malloc(len);
  memcpy(buffer, packet, len);

  /* EXTRACT ETHERNET HEADER FROM PACKET*/
  sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(buffer); 

  /*
    Check destination mac address
    matches the coresponding interface
    at which packet was received
   */

  sr_if_t *iface = sr_get_interface(sr, interface);
  print_hdr_eth((uint8_t *)ether_header);
  sr_print_if(iface);
  uint8_t broadcast_addr[ETHER_ADDR_LEN];
  memset(broadcast_addr, 0xFF, ETHER_ADDR_LEN);
  /*
  print_addr_eth(ether_header->ether_dhost);
  print_addr_eth(broadcast_addr);
  */


  if((memcmp(ether_header->ether_dhost,broadcast_addr,ETHER_ADDR_LEN) != 0)  && 
  (memcmp(ether_header->ether_dhost,iface->addr,ETHER_ADDR_LEN) != 0)) {
    fprintf(stderr,"Destination mac address does not match interface mac address \n");
    free(buffer);
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
     print_hdr_arp((uint8_t*)arp_header);

    if(ntohs(arp_header->ar_op) == arp_op_reply) {

      process_arpreply(sr, arp_header);

    /* Process the ARP request */
    } else {

     printf("... RECEIVED ARP REPLY\n");
     /* send arp reply to the ARP request*/
      send_arpreply(sr, arp_header, interface);
     printf("... SENT ARP REPLY\n");
    }

  } else if (ntohs(ether_header->ether_type) == ethertype_ip) {

    /* Verify checksum, if fail: drop/free the packet*/
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(buffer + ETHER_HDR_LEN);
    print_hdr_ip((uint8_t *)ip_header);
    uint16_t checksum = cksum(ip_header, IP_HDR_LEN);
    if(checksum != 0xFFFF) {
        fprintf(stderr, "Invalid checksum %d\n", checksum);
        free(buffer);
        return;
    }

    /* If destined to the router/interface
       what is the protcol field in IP header
       ICMP -> ICMP processing (echo request, echo reply)
       UDP,TCP -> ICMP port unreachable
    */
    if(ntohl(ip_header->ip_dst) == ntohl(iface->ip)) {

        if(ip_header->ip_p == ip_protocol_icmp) {

            /* ICMP -> ICMP processing (echo request, echo prely) */
            icmp_send_echo_reply(sr, buffer, len, interface);
        } else {

            /* UDP,TCP -> ICMP port unreachable */
            icmp_send_error(sr, buffer, len, interface,
                            ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACH);
        }

    } else {

      ip_header->ip_ttl -= 1;
      sr_rt_t* rt_entry = sr_get_rt_entry(sr, ip_header->ip_dst);

      /*
          If destined to others, lookup routing table entry  note that gateway is next hop
          decrease TTL, If TTL = 0; ICMP Time exceeded
      */
      if(ip_header->ip_ttl <= 0) {
        /* ICMP Time exceeded */
        icmp_send_error(sr, buffer, len, interface,
                        ICMP_TYPE_TIME_EXCEEDED, 0);
      } else {
      /*
          based on returned routing entry:

          if routing entry not found (is NULL) -> ICMP  network unreachable
          if routing entry is found, get mac_address of next_hop using gateway address
            # When sending packet to next_hop_ip
            entry = arpcache_lookup(next_hop_ip)

            if entry:
                use next_hop_ip->mac mapping in entry to send the packet
                free entry
                free packet sent
            else:
                req = arpcache_queuereq(next_hop_ip, packet, len)
                handle_arpreq(req)
                The packet argument should not be freed by the caller.
      */
        if(rt_entry == NULL) {
          /* ICMP network unreachable */
          icmp_send_error(sr, buffer, len, interface,
                          ICMP_TYPE_UNREACHABLE, ICMP_CODE_NET_UNREACH);
        } else {

          /* update checksum in IP header*/
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum(ip_header, IP_HDR_LEN);

          /* next hop is determined by gateway address from routing entry*/
          in_addr_t next_hop_ip = rt_entry->gw.s_addr;
          /* intially set the destination mac_address to 0x0000*/
          memset(ether_header->ether_dhost, 0, ETHER_ADDR_LEN);
          ether_header->ether_type = htons(ethertype_ip);
          /* get infromation regarding the gateways interface*/
          sr_if_t* gw_iface = sr_get_interface(sr, rt_entry->interface);
          memcpy(ether_header->ether_shost, gw_iface->addr,  ETHER_ADDR_LEN);

          /* get arp entry*/
          sr_arpentry_t* arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
          if(arp_entry != NULL) {

            fprintf(stderr, "\n\nArp entry found! Packet being sent.\n\n");
            /* copy over mac address we just found */
            memcpy(ether_header->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, buffer, len, rt_entry->interface);

            fprintf(stderr, "\n\nPacket Forwarded \n\n");
            free(arp_entry);
            free(buffer);

          } else {

             fprintf(stderr, "Arp entry not found! Packet put in queue.\n");

            /* 
              queue packet into cache
              DON'T FREE PACKET
             */
            sr_arpreq_t* req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, buffer, len, rt_entry->interface);
            handle_arpreq(sr, req);

          }
        } /* end  rt_entry not null */
      } /* end  ttl > 0 */
    }/* end destined to other router */


  }


}/* end sr_ForwardPacket */

/**
 * swap_ether_addr
 * @param ether_header
 * Swaps the src and dst MAC addresses
 */
void swap_ether_addr(sr_ethernet_hdr_t *ether_header) {
    uint8_t dhost[ETHER_ADDR_LEN];
    memcpy(dhost, ether_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_shost, ether_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_dhost, dhost, ETHER_ADDR_LEN);
}

/**
 * calculate_ip_cksum
 * clears cksum field, calculates ip checksum
 */
void calculate_ip_cksum(sr_ip_hdr_t *ip_header) {
    ip_header->ip_sum = 0;
    /*memset(&(ip_header->ip_sum), 0, sizeof(ip_header->ip_sum));*/
    uint16_t checksum = cksum(ip_header, IP_HDR_LEN);
    ip_header->ip_sum = checksum;
}

/**
 * icmp_send_echo_reply
 * type 0 ICMP
 * @param sr_instance *sr
 * @param uint8_t *packet - includes ethernet headers 
    Can overwrite and reuse this packet to send.
 * @param unsigned int leng
 * @param char* interface - name of interface
 */
void icmp_send_echo_reply(struct sr_instance *sr, uint8_t *packet,
                        unsigned int len, const char *interface) {

    sr_if_t *iface = sr_get_interface(sr, interface);

    /*** PREPARE ETHER HEADER - just switch source and dest */
    sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(packet);
    swap_ether_addr(ether_header);
    /* the ether_type should be the same */

    /*** PREPARE IP HEADER */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + ETHER_HDR_LEN);

    /* Use random id and long ttl */
    ip_header->ip_id = rand() % 10000;
    ip_header->ip_ttl = INIT_TTL;

    /* Flip the source and destination addresses */
    uint32_t new_ip_src = ip_header->ip_dst;
    ip_header->ip_dst = ip_header->ip_src;
    ip_header->ip_src = new_ip_src;

    /* calculate the new checksum for this ip header */
    calculate_ip_cksum(ip_header);

    /* Should be equivalent to ip_header->ip_len - IP_HDR_LEN */
    unsigned int icmp_length =
        len - ETHER_HDR_LEN - IP_HDR_LEN;

    /* Check ICMP checksum. for echo's, include the data in the checksum */
    /*  The checksum is the 16-bit ones's complement of the one's
    complement sum of the ICMP message starting with the ICMP Type.
    For computing the checksum , the checksum field should be zero.
    If the total length is odd, the received data is padded with one
    octet of zeros for computing the checksum.  This checksum may be
    replaced in the future.
    */
    unsigned int icmp_cksumming_length = icmp_length;
    if (icmp_length % 2 != 0) {
        ++icmp_cksumming_length;
    }

    uint8_t *icmp_cksum_pkt = (uint8_t *)malloc(icmp_cksumming_length);
    memset(icmp_cksum_pkt, 0, icmp_cksumming_length); /* pad octet of zeros */
    memcpy(icmp_cksum_pkt, packet + ETHER_HDR_LEN + IP_HDR_LEN, icmp_length);
    uint16_t checksum = cksum(icmp_cksum_pkt, icmp_cksumming_length);
    if ( checksum != 0xFFFF) { /* no need to clear if check against 0xFFFF */
        /* TODO
           What to do here? 
         */
        fprintf(stderr, "Invalid checksum %hu\n", checksum);
        free(icmp_cksum_pkt);
        return;
    }
    free(icmp_cksum_pkt);

    /**** Prepare the ICMP header */
    /* identifier and sequence numbers are returned the same */
    sr_icmp_t0_hdr_t *icmp_t0 =
        (sr_icmp_t0_hdr_t *)(packet + ETHER_HDR_LEN + IP_HDR_LEN);

    /* Type 0, code 0 */
    icmp_t0->icmp_type = ICMP_TYPE_ECHO_REPLY;
    icmp_t0->icmp_code = 0;

    /* calculate new checksum */
    icmp_t0->icmp_sum = 0;
    /* memset(&(icmp_t0->icmp_sum), 0, sizeof(icmp_t0->icmp_sum));*/
    icmp_cksum_pkt = (uint8_t *) icmp_t0; /* use the pointer as an array now */
    checksum = cksum(icmp_cksum_pkt, icmp_length);
    icmp_t0->icmp_sum = checksum;

    sr_send_packet(sr, packet, len, iface->name);
}

/**
 * icmp_send_error
 * type 3 and 11 ICMP
 * @param sr_instance *sr
 * @param uint8_t *packet - includes ethernet headers
 * @param unsigned int len
 * @param char* interface - name of interface
 * @param uint8_t type - ICMP type
 * @param uint8_t code - ICMP code
 */
void icmp_send_error(struct sr_instance *sr, uint8_t *packet,
                     unsigned int len, const char *interface,
                     uint8_t type, uint8_t code) {

    sr_if_t *iface = sr_get_interface(sr, interface);

    unsigned int packet_size = ETHER_HDR_LEN + IP_HDR_LEN + ICMP_ERR_HDR_LEN;
    uint8_t *dup_packet = malloc(packet_size);
    memcpy(dup_packet, packet, packet_size);

    /* PREPARE ETHER HEADER - just switch source and dest */
    sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(dup_packet);
    swap_ether_addr(ether_header);
    /* the ether_type should be the same */

    /* PREPARE IP HEADER */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(dup_packet + ETHER_HDR_LEN);

    /* Update total length depending on ICMP data */
    ip_header->ip_len = IP_HDR_LEN + ICMP_ERR_HDR_LEN;

    /* Use long ttl */
    /* TODO: what ttl to use for type 3 unreachable and 11 time exceeded? */
    ip_header->ip_ttl = INIT_TTL;

    /* Use protocol ICMP */
    ip_header->ip_p = ip_protocol_icmp;

    /* Use this interface's ip */
    ip_header->ip_src = iface->ip;
    ip_header->ip_dst = ip_header->ip_src;

    /* calculate the new checksum for this ip header */
    calculate_ip_cksum(ip_header);

    /* Prepare the ICMP header */
    sr_icmp_err_hdr_t *icmp_err =
        (sr_icmp_err_hdr_t *)(dup_packet + ETHER_HDR_LEN + IP_HDR_LEN);

    /* Type, code */
    icmp_err->icmp_type = type;
    icmp_err->icmp_code = code;

    /* types 3, 11 return the IP header + 8 bytes of original datagram data */
    /* Copy the IP header */
    memcpy(&(icmp_err->data), ip_header, IP_HDR_LEN);
    /* Copy the first 8 bytes of the original datagram data */
    memcpy(&(icmp_err->data) + IP_HDR_LEN,
        dup_packet + ETHER_HDR_LEN + IP_HDR_LEN, ICMP_DATA_SIZE - IP_HDR_LEN);

    /* Calculate the new checksum for the icmp*/
    icmp_err->icmp_sum = 0;
    /*memset(&(icmp_err->icmp_sum), 0, sizeof(icmp_t11->icmp_sum));*/

    uint16_t checksum = cksum(icmp_err, ICMP_ERR_HDR_LEN);
    icmp_err->icmp_sum = checksum;

    sr_send_packet(sr, dup_packet, len, iface->name);
    free(dup_packet);
}

