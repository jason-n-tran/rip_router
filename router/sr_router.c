/**********************************************************************
 * file:  sr_router.c
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
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    
} /* -- sr_init -- */

/* return 0 if not valid, 1 if valid */
int validate_packet(uint8_t* packet_buffer,int packet_len){

  return 1;

}


struct sr_rt* longest_prefix_match(struct sr_instance* sr,uint32_t ip_adr){
  struct sr_rt* longest_match_rt = NULL;
  unsigned long max_len = 0; 

  struct sr_rt* rt_iter;

}

/* DEPRECATED Maybe?*/
int send_ethernet_frame(struct sr_instance* sr,
                         uint8_t* packet_buffer,
                         unsigned int len,
                         uint32_t dest_ip_adr)
{
  struct sr_rt* matched_rt = longest_prefix_match(sr,dest_ip_adr);

  return 1;
}

int send_icmp_error_message(struct sr_instance* sr,
                            char* interface_name,
                            uint16_t ip_id,
                            uint8_t* payload_from_error_datagram_buffer, /* first 28 bytes */
                            uint32_t dest_ip_adr,
                            uint32_t src_ip_adr,
                            uint8_t  ether_dhost[ETHER_ADDR_LEN],   /* destination ethernet address */
                            uint8_t  ether_shost[ETHER_ADDR_LEN],  /* source ethernet address */
                            int icmp_error_msg_type /* ICMP Error Message Type, defined in sr_router.h */
)
{

  uint32_t total_len;
  
}


/* return 1 if sent successfully, 0 if error.  */
int send_icmp_echo_reply(struct sr_instance* sr,
                         struct sr_if* iface,
                         uint16_t ip_id,
                         uint8_t* additional_data_buffer,
                         uint32_t additional_data_len,
                         uint32_t dest_ip_adr,
                         uint32_t src_ip_adr,                      
                         uint8_t  ether_dhost[ETHER_ADDR_LEN],   /* destination ethernet address */
                         uint8_t  ether_shost[ETHER_ADDR_LEN]  /* source ethernet address */
)
{

    /* construct ethernet frame */
    uint32_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)+additional_data_len; /* leave last 4 bytes empty */
    uint8_t* buf = (uint8_t*) malloc(total_len);

}

/* return 1 if sent successfully, 0 if error.  */
int send_arp_reply(struct sr_instance* sr,
                  char* name,
                  uint32_t target_ip_adr,
                  uint32_t sender_ip_adr,
                  uint8_t  ether_dhost[ETHER_ADDR_LEN],   /* destination ethernet address */
                  uint8_t  ether_shost[ETHER_ADDR_LEN]  /* source ethernet address */
)
{
  /* construct ethernet frame */
  uint32_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
  uint8_t* buf = (uint8_t*) malloc(total_len);


}

/* return 1 if sent successfully, 0 if error.  */
int send_arp_request(struct sr_instance* sr,
                  uint32_t target_ip_adr
)
{
  
  /* Gather necessary information */
  struct sr_rt* matched_rt = longest_prefix_match(sr,target_ip_adr);
  struct sr_if* out_iface = sr_get_interface(sr,matched_rt->interface);
  
}



int compare_two_name(char* a, char* b,int len){
  int i;
  for(i=0;i<len;i++){
    if(*a!=*b){
      return 0;
    }
    a++;
    b++;
  }
  return 1;
}

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
  
}/* end sr_ForwardPacket */
