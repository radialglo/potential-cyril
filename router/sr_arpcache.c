#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    
    /*
    for each request on sr->cache.requests:
         handle_arpreq(request)
    */
    sr_arpreq_t *req = sr->cache.requests;
    sr_arpreq_t *next;
    while(req != NULL) {
    /*
    Since handle_arpreq as defined in the comments above could destroy your
    current request, make sure to save the next pointer before calling
    handle_arpreq when traversing through the ARP requests linked list.
    */
        next = req->next;
        handle_arpreq(sr,req);
        req = next;
    }

}

/**
 * handle_arpreq - handles ARP Request
 * @param sr_instance *sr
 * @param sr_arpreq *req
 *
 * To meet the guidelines in the assignment (ARP requests are sent every second
 * until we send 5 ARP requests, then we send ICMP host unreachable back to
 * all packets waiting on this ARP request), you must fill out the following
 * function that is called every second and is defined in sr_arpcache.c:
 */
void handle_arpreq(struct sr_instance *sr, sr_arpreq_t *req) {

    time_t now;
    time(&now);

    /* if its been a second and time to send another requests */
    if(difftime(now,req->sent) > 1.0) {
        if(req->times_sent >= REQUEST_LIMIT) {
            /* TODO
            send icmp host unreachable to source addr of all pkts waiting
                on this request
             */
        } else {
          send_arpreq(sr,req->ip);
          req->sent = now;
          req->times_sent++;
        }
    }

}

/**
 * send_arpreq
 * builds and ethernet frame and broadcast the frame
 * @param sr_instance *sr
 * @param uint32_t ip - target/destination ip address
 */
void send_arpreq(struct sr_instance *sr, uint32_t ip) {

    /*-------------|------------
     | Ether Header| ARP Header |
     --------------|-----------*/
    /*
      prepend ethernet header to arp header before sending
      sr_send_packet requires ethernet header 
    */
    unsigned int total_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* buffer = malloc(total_length);

    sr_rt_t* rt = sr_get_rt_entry(sr, ip);
    sr_if_t* interface = sr_get_interface(sr, rt->interface);

    /* PREPARE ETHERNET HEADER */
    sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)(buffer);
    /* set up broadcast address*/
    memset(ether_header->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    ether_header->ether_type = htons(ethertype_arp);

    /* PREPARE ARP HEADER */
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));

    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = ethertype_ip;
    arp_header->ar_hln = ETHER_ADDR_LEN;
    arp_header->ar_pln = IP_ADDR_LEN;
    arp_header->ar_op  = htons(arp_op_request);

    /* target ip and hardware addresses */
    arp_header->ar_tip = ip;
    /* hardware address to TBD  */
    memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN );

    /* src hardware and ip addresses
       this part is a bit confusing
       sr_send_packet will send packet to interface
       which will be injected into link layer by that interface.
       So the source ip corresponds to that interface's ip
     */
    arp_header->ar_sip = interface->ip;
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN );

    sr_send_packet(sr, buffer, total_length, interface->name );
    free(buffer);

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

