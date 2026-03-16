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
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/* return 0 if not valid, 1 if valid */
int validate_packet(uint8_t* packet_buffer,int packet_len){

  /* minimum length */
  if (packet_len<sizeof(sr_ethernet_hdr_t)){
    fprintf(stderr,"packet length less than minimumm length of ethernet frame.");
  }

  if(ethertype(packet_buffer)==ethertype_ip){
    /* ip packet */
    if(packet_len<sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)){
      fprintf(stderr,"packet length less than minimumm length of ethernet frame with IP payload");
      return 0;
    }

    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t*) (packet_buffer+sizeof(sr_ethernet_hdr_t));
    if(cksum(ip_header,sizeof(sr_ip_hdr_t))!=0xFFFF){
      fprintf(stderr,"checksum for IP header does not pass");
      return 0;
    }

    if(ip_protocol(packet_buffer+sizeof(sr_ethernet_hdr_t))==ip_protocol_icmp){
      /* ICMP */
      if(packet_len<sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)){
        fprintf(stderr,"packet length less than minimum length of ethernet frame with IP payload with ICMP msg");
        return 0;
      }

      sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t*) (packet_buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      if(cksum(icmp_header,packet_len-sizeof(sr_ip_hdr_t)-sizeof(sr_ethernet_hdr_t))!=0xFFFF){
        fprintf(stderr,"checksum for ICMP msg does not pass");
        return 0;
      }

    }
  }else if(ethertype(packet_buffer)==ethertype_arp){
    /* ARP */
    if(packet_len<sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t)){
      fprintf(stderr,"packet length less than minimumm length of ethernet frame with ARP payload");
      return 0;
    }

  }else{
    fprintf(stderr,"ethernet frame has no valid ether_type");
    return 0;
  }

  return 1;

}


struct sr_rt* longest_prefix_match(struct sr_instance* sr,uint32_t ip_adr){
  struct sr_rt* longest_match_rt = NULL;
  unsigned long max_len = 0; 

  struct sr_rt* rt_iter;

  for(rt_iter = sr->routing_table;rt_iter!=NULL;rt_iter=rt_iter->next){
    if((rt_iter->dest.s_addr&rt_iter->mask.s_addr)==(ip_adr & rt_iter->mask.s_addr) && (rt_iter->mask.s_addr>=max_len)){
      max_len = rt_iter->mask.s_addr;
      longest_match_rt = rt_iter;
    }
  }
  return longest_match_rt;
}

/* DEPRECATED Maybe?*/
int send_ethernet_frame(struct sr_instance* sr,
                         uint8_t* packet_buffer,
                         unsigned int len,
                         uint32_t dest_ip_adr)
{
  struct sr_rt* matched_rt = longest_prefix_match(sr,dest_ip_adr);

  if(matched_rt==NULL){
    /*TODO: send ICMP net unreachable */
  }
  int res = sr_send_packet(sr,packet_buffer,len,matched_rt->interface); /* 0 is success, -1 is failure */
  if(res!=0){
    return 0;
  }
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

  /* construct ethernet frame */
  uint32_t total_len;
  if(icmp_error_msg_type==ICMP_TIME_EXCEEDED){
    /* Type 11 hdr */
    total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t);
  }else{
    /* Type 3 hdr */
    total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
  }
  uint8_t* buf = (uint8_t*) malloc(total_len);

  /*  set up ethernet frame header */
  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
  memcpy(eth_header->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
  memcpy(eth_header->ether_shost,ether_shost,ETHER_ADDR_LEN);
  eth_header->ether_type = htons(ethertype_ip);

  /* set up ip header */
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5; /* in 32-bit words */
  ip_header->ip_tos = 0; 
  ip_header->ip_len = htons(total_len - sizeof(sr_ethernet_hdr_t));
  ip_header->ip_id = ip_id; 
  ip_header->ip_off = htons(IP_DF);
  ip_header->ip_ttl = 64;
  ip_header->ip_p = ip_protocol_icmp;
  ip_header->ip_src = src_ip_adr;
  ip_header->ip_dst = dest_ip_adr;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));

  /* set ICMP header */
  if(icmp_error_msg_type==ICMP_TIME_EXCEEDED){
    sr_icmp_t11_hdr_t* icmp_header = (sr_icmp_t11_hdr_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_header->icmp_type = 11;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_sum = 0;
    memcpy(icmp_header->data,payload_from_error_datagram_buffer,ICMP_DATA_SIZE);
    icmp_header->icmp_sum = cksum(icmp_header,sizeof(sr_icmp_t11_hdr_t));
  }else{
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_header->icmp_type = 3;
    switch (icmp_error_msg_type)
    {
      case ICMP_DESTINATION_NET_UNREACHABLE:
        icmp_header->icmp_code = 0;
        break;
      case ICMP_DESTINATION_HOST_UNREACHABLE:
        icmp_header->icmp_code = 1;
        break;
      case ICMP_PORT_UNREACHABLE:
        icmp_header->icmp_code = 3;
        break;
      default:
        break;
    }
    icmp_header->icmp_sum = 0;
    memcpy(icmp_header->data,payload_from_error_datagram_buffer,ICMP_DATA_SIZE);
    icmp_header->icmp_sum = cksum(icmp_header,sizeof(sr_icmp_t3_hdr_t));
  }
  
  /* send ethernet frame */
  int is_success = sr_send_packet(sr,buf,total_len,interface_name); /* 0 is success, -1 is failure */
  free(buf);
  return is_success;
  
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

   /*  set up ethernet frame header */
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
    memcpy(eth_header->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost,ether_shost,ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ethertype_ip);

    /* print_hdr_eth((uint8_t*)eth_header); */
    /* set up ip header */
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5; /* in 32-bit words */
    ip_header->ip_tos = 0; 
    ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + additional_data_len+sizeof(sr_icmp_hdr_t));
    ip_header->ip_id = ip_id; 
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_ttl = 64;
    ip_header->ip_p = ip_protocol_icmp;
    ip_header->ip_src = src_ip_adr;
    ip_header->ip_dst = dest_ip_adr;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));
    /* print_hdr_ip((uint8_t *)ip_header); */

    /* set ICMP header */
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_header->icmp_type = 0;
    icmp_header->icmp_code = 0;
    

    /* Fill in section after the header (including seq id and data section)*/
    uint8_t* ptr = ((uint8_t*) icmp_header) + sizeof(sr_icmp_hdr_t);
    memcpy(ptr,additional_data_buffer,additional_data_len);
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header,sizeof(sr_icmp_hdr_t)+additional_data_len);
    
  
    int is_success = sr_send_packet(sr,buf,total_len,iface->name); /* 0 is success, -1 is failure */
    
    return is_success;
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

  /*  set up ethernet frame header */
  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
  memcpy(eth_header->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
  memcpy(eth_header->ether_shost,ether_shost,ETHER_ADDR_LEN);
  eth_header->ether_type = htons(ethertype_arp);

  /* set up arp header */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = sizeof(uint32_t); /* 4 bytes */
  arp_header->ar_op = htons(arp_op_reply);
  memcpy(arp_header->ar_sha,ether_shost,ETHER_ADDR_LEN);
  memcpy(arp_header->ar_tha,ether_dhost,ETHER_ADDR_LEN);
  arp_header->ar_sip = sender_ip_adr;
  arp_header->ar_tip = target_ip_adr;

  
  int is_success = sr_send_packet(sr,buf,total_len,name); /* 0 is success, -1 is failure */
  free(buf);
  
  return is_success;

}

/* return 1 if sent successfully, 0 if error.  */
int send_arp_request(struct sr_instance* sr,
                  uint32_t target_ip_adr
)
{
  

  /* Gather necessary information */
  struct sr_rt* matched_rt = longest_prefix_match(sr,target_ip_adr);
  struct sr_if* out_iface = sr_get_interface(sr,matched_rt->interface);
  /* TODO: WHAT IF matched_rt is NULL */

  /*DEBUG
  struct in_addr dest_addr;
  struct in_addr src_addr;
  dest_addr.s_addr = target_ip_adr;
  src_addr.s_addr = out_iface->ip;
  printf("sending arp request \n");
  printf("from: %s \n ",inet_ntoa(src_addr));
  printf("to %s \n ",inet_ntoa(dest_addr));
  */

  /* construct ethernet frame */
  uint32_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
  uint8_t* buf = (uint8_t*) malloc(total_len);

  /*  set up ethernet frame header */
  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
  memset(eth_header->ether_dhost,255,ETHER_ADDR_LEN); /* Broadcast address, all bits set to 1 */
  memcpy(eth_header->ether_shost,out_iface->addr,ETHER_ADDR_LEN);
  eth_header->ether_type = htons(ethertype_arp);

  /* set up arp header */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = sizeof(uint32_t); /* 4 bytes */
  arp_header->ar_op = htons(arp_op_request);
  memcpy(arp_header->ar_sha,out_iface->addr,ETHER_ADDR_LEN);
  memset(arp_header->ar_tha,0,ETHER_ADDR_LEN); /* target hardware address leave it 00:00:00:00:00:00 */
  arp_header->ar_sip = out_iface->ip;
  arp_header->ar_tip = target_ip_adr;

  
  int is_success = sr_send_packet(sr,buf,total_len,out_iface->name); /* 0 is success, -1 is failure */
  free(buf);
  
  return is_success;
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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* incoming interface */
  struct sr_if* iface = sr_get_interface(sr,interface);

  /* sanity check the package */
  if(!validate_packet(packet,len)){
    return;
  }

  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) packet;
  if(eth_header->ether_type == htons(ethertype_ip)){
    /* IP packet */
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if* if_iter;

    int is_own = 0; /* bool flag for if destinatino IP is router's own interface */
    
    if ((ip_header->ip_dst << 24) >> 24 == 255){ /*Is it a broadcast address*/
      if(ip_header->ip_p == ip_protocol_udp){
        struct sr_udp_hdr* udp_header = (sr_udp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        if((htons(udp_header->port_src) == 520) & (htons(udp_header->port_dst) == 520)){ /*RIP Packet*/
          sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
          if(rip_packet->command == 1){ /*RIP Request*/
            send_rip_response(sr);
          }
          if(rip_packet->command == 2){ /*RIP Response*/
            update_route_table(sr,packet,len,interface);
          }
        }else{
          /* return ICMP Destination Port unreachable*/
          send_icmp_error_message(
            sr,
            iface->name,
            ip_header->ip_id,
            (uint8_t*)ip_header,
            ip_header->ip_src,
            iface->ip,
            eth_header->ether_shost,
            iface->addr,
            ICMP_PORT_UNREACHABLE
          );
        }
      }else{
        /* Do nothing here?*/
      }
      return;
    }



    for(if_iter = sr->if_list;if_iter!=NULL;if_iter = if_iter->next){
      if(if_iter->ip==ip_header->ip_dst){
        is_own = 1;
        /* sent to one of router's own interfaces */
        if(sr_obtain_interface_status(sr,if_iter->name)==0){
          /* interface down, sent ICMP Destination net unreachable back to sender*/
          printf("pinging downed interface sent icmp \n");
          send_icmp_error_message(
            sr,
            iface->name,
            ip_header->ip_id,
            (uint8_t*)ip_header,
            ip_header->ip_src,
            iface->ip,
            eth_header->ether_shost,
            iface->addr,
            ICMP_DESTINATION_NET_UNREACHABLE
          );
          return;
        }


        if(ip_header->ip_p==ip_protocol_icmp){
          /* ICMP packet */
          sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          if(icmp_header->icmp_type==8){
            /* ICMP echo request, need to process explicitly */
            /* checksum is valid as validated before */

            
            /* send an ICMP echo reply to the sending hosts */
            send_icmp_echo_reply(
              sr,
              iface,
              ip_header->ip_id,
              ((uint8_t*) icmp_header) + 4,
              len - sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t)-sizeof(sr_ethernet_hdr_t),
              ip_header->ip_src,
              ip_header->ip_dst,
              eth_header->ether_shost,
              eth_header->ether_dhost
            );
            
          }
        }else{
          /* Not an ICMP packet */
          send_icmp_error_message(
              sr,
              iface->name,
              ip_header->ip_id,
              (uint8_t*)ip_header,
              ip_header->ip_src,
              iface->ip,
              eth_header->ether_shost,
              iface->addr,
              ICMP_PORT_UNREACHABLE
            );

        }
        break;
      }
    }

    if(!is_own){
      if(sr_obtain_interface_status(sr,interface)==0){
        /* interface down, sent ICMP Destination net unreachable back to sender*/
        send_icmp_error_message(
          sr,
          iface->name,
          ip_header->ip_id,
          (uint8_t*)ip_header,
          ip_header->ip_src,
          iface->ip,
          eth_header->ether_shost,
          iface->addr,
          ICMP_DESTINATION_NET_UNREACHABLE
        );
        return;
      }
      /* Forwarding logic */
      if(ip_header->ip_ttl==1){
        /* TTL ==1, send time exceeded back to sender */
        send_icmp_error_message(
          sr,
          iface->name,
          ip_header->ip_id,
          (uint8_t*)ip_header,
          ip_header->ip_src,
          iface->ip,
          eth_header->ether_shost,
          iface->addr,
          ICMP_TIME_EXCEEDED
        );
      }else{
        struct sr_rt* matched_rt = longest_prefix_match(sr,ip_header->ip_dst);
        /*DEBUG
        struct in_addr target_ip,next_hop_ip;
        target_ip.s_addr = ip_header->ip_dst;
        next_hop_ip.s_addr = matched_rt->gw.s_addr;
        printf("tyring to forward, target ip: %s \n",inet_ntoa(target_ip));
        printf("tyring to forward, next hop ip: %s \n",inet_ntoa(next_hop_ip));
        */



        if(matched_rt==NULL||matched_rt->metric==INFINITY){
          /*TODO: send ICMP net unreachable */
          /*delete line:  matched_rt = longest_prefix_match(sr,ip_header->ip_src);*/
         
          send_icmp_error_message(
            sr,
            iface->name, /* update this to be consistent*/
            ip_header->ip_id,
            (uint8_t*)ip_header,
            ip_header->ip_src,
            iface->ip,
            eth_header->ether_shost,
            iface->addr,
            ICMP_DESTINATION_NET_UNREACHABLE
          );
          return;
        }

        /* Need to forward package */
        ip_header->ip_ttl--;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));
        
        struct sr_arpentry* cached_arp_entry=NULL;
        uint32_t next_destination_ip = 0;

        /*!!! Key fix from previous version !!!*/
        if(matched_rt->gw.s_addr==0){
          /* directly connect to router, use target ip*/
          next_destination_ip = ip_header->ip_dst;
        }else{
          /* not directly connect to router, use next hop*/
          next_destination_ip = matched_rt->gw.s_addr;
        }

        cached_arp_entry = sr_arpcache_lookup(&sr->cache, next_destination_ip);

	      
        /* Copy the source MAC first to packet */
        memcpy(eth_header->ether_shost,sr_get_interface(sr,matched_rt->interface)->addr, ETHER_ADDR_LEN);

        if(cached_arp_entry!=NULL){
          /* Can Send immediately*/
		      memcpy(eth_header->ether_dhost, cached_arp_entry->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr,packet,len,matched_rt->interface);
          /*printf("forwarded packet\n");*/
          free(cached_arp_entry);
          return;
        }else{
          /* Cache Miss*/
          /*struct in_addr target_ip;
          target_ip.s_addr = next_destination_ip;
          printf("cache miss, dont know mac for %s \n",inet_ntoa(target_ip));*/
          struct sr_arpreq *req;
          req = sr_arpcache_queuereq(&sr->cache, next_destination_ip, packet, len, matched_rt->interface);
          handle_arpreq(sr,req);         
          return;
        }
      }

    }

  }else if(eth_header->ether_type == htons(ethertype_arp)){
    /* got an ARP message*/
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
    
    struct sr_if* if_iter;
    for(if_iter = sr->if_list;if_iter!=NULL;if_iter = if_iter->next){
      if(if_iter->ip==arp_header->ar_tip){ /* Only process if this is destined towards one of router interface's address */
        if(arp_header->ar_op==htons(arp_op_request)){
          /* receive ARP request */
          send_arp_reply(sr,
                         if_iter->name,
                         arp_header->ar_sip,
                         arp_header->ar_tip,
                         arp_header->ar_sha,
                         if_iter->addr);/* send ARP reply to sender */
        printf("client MAC from arp request:");
        print_addr_eth(arp_header->ar_sha);

        }else{
          /* receive ARP reply*/
          /*printf("Received ARP reply\n");*/
          struct sr_arpreq *req;
          req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

          /* If pending requests, send all packets  */
          if(req){
            
            /* Send all packets on pending lists */
            struct sr_packet *packets_iter;
            packets_iter = req->packets;
            while(packets_iter!=NULL){
              /* Loop through the linked list */
              sr_ethernet_hdr_t* pac_eth_header = (sr_ethernet_hdr_t*) packets_iter->buf;
              memcpy(pac_eth_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN); /* Use the newly received MAC address */
              sr_send_packet(sr,packets_iter->buf,packets_iter->len,packets_iter->iface);
              packets_iter = packets_iter->next;
              /*printf( "sent pending packet..\n");*/
            }
            sr_arpreq_destroy(&(sr->cache), req);
          }
        }

      }

    }

  }
  

}/* end sr_ForwardPacket */
