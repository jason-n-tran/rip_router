/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_locker));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_locker));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_locker));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_locker));

        /* check expiration*/
        struct sr_rt* rt_walker = 0;
        rt_walker = sr->routing_table;
        while(rt_walker){
            if(difftime(time(NULL),rt_walker->updated_time)>=20)
                /* instead of deleting, set metric to infinity*/
                /* TODO:need to ensure look up in other places ignore entires w/ infinity*/
                rt_walker->metric = INFINITY;
            rt_walker = rt_walker->next;
        }

        /* check router's own interface status*/
        struct sr_if* if_walker = 0;
        if_walker = sr->if_list;
        while(if_walker){
            if(sr_obtain_interface_status(sr,if_walker->name)==0){
                printf("interface down: %s \n",if_walker->name);
                /* interface down, delete all entries sent from this interface*/
                rt_walker = sr->routing_table;
                while(rt_walker){
                    
                    if(strcmp(rt_walker->interface,if_walker->name)==0){
                        rt_walker->metric = INFINITY;
                        printf("entry deleted (set to INFINITY) \n");
                    }
                        
                    rt_walker = rt_walker->next;
                }

            }else{
                /* interface up, check routing table*/
                int contain_subnet = 0; /* entry in rt (could be invalid e.g. infinity)*/
                rt_walker = sr->routing_table;
                while(rt_walker){
                    if ((if_walker->ip & if_walker->mask) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)){
                        
                        if(rt_walker->metric!=INFINITY){
                            /* contains subnet and valid, update time*/
                            rt_walker->updated_time = time(NULL);
                        }else{
                            /*contains subnet but was invalid, add it back*/
                            rt_walker->metric  = (uint32_t)0;
                            strcpy(rt_walker->interface,if_walker->name);
                            rt_walker->gw.s_addr = 0;
                        }
                        contain_subnet = 1;
                    }
                    rt_walker = rt_walker->next;
                }

                if(contain_subnet==0){
                    printf("!!does not contain subnet netry, add new...\n");
                    /* does not contain entry, add new entry to routing table*/
                    /* most likely will not be called*/
                    char  iface[32];
                    struct in_addr dest_addr;
                    struct in_addr gw_addr;
                    struct in_addr mask_addr;
                    dest_addr.s_addr = if_walker->ip & if_walker->mask;
                    gw_addr.s_addr = 0;
                    mask_addr.s_addr = if_walker->mask;
                    strcpy(iface, if_walker->name);
                    sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
                }
            }

            if_walker = if_walker->next;
        }
        
        printf("Routing Table in timeout: \n");
        sr_print_routing_table(sr); 
        printf("\n");
        /* send out rip response*/
        send_rip_response(sr);
        
        pthread_mutex_unlock(&(sr->rt_locker));
    }
    return NULL;
}

/* compute udp cksum (w/ pseudo header)*/
uint16_t udp_cksum(sr_ip_hdr_t* ip_header){
  
  uint16_t total_len  = ntohs(ip_header->ip_len)-sizeof(sr_ip_hdr_t)+sizeof(sr_ip_pseudo_header_t);
  uint8_t* buf = (uint8_t*) malloc(total_len);

  /* copy over udp header + data*/
  memcpy(buf+sizeof(sr_ip_pseudo_header_t),(uint8_t*)ip_header+sizeof(sr_ip_hdr_t),total_len-sizeof(sr_ip_pseudo_header_t));
  
  /* construct pseudo header*/
  sr_ip_pseudo_header_t* pseudo_header = (sr_ip_pseudo_header_t*) buf;
  pseudo_header->ip_src = ip_header->ip_src;
  pseudo_header->ip_dst = ip_header->ip_dst;
  pseudo_header->protocol = ip_header->ip_p;
  pseudo_header->total_length = ip_header->ip_hl;
  pseudo_header->unused = 0;


  /* compute checksum, need to verify if this logic works */
  uint16_t ret =  cksum(buf,total_len);
  free(buf);
  return ret;
}

void send_rip_request(struct sr_instance *sr){
    printf("sending RIP request\n");
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_if* if_iter;
    for(if_iter = sr->if_list;if_iter!=NULL;if_iter = if_iter->next){
        /* for each interface, send request */

        /* construct ethernet frame */
        uint32_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
        uint8_t* buf = (uint8_t*) malloc(total_len);

        /*  set up ethernet frame header */
        sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
        memset(eth_header->ether_dhost,255,ETHER_ADDR_LEN); /* Broadcast address, all bits set to 1 */
        memcpy(eth_header->ether_shost,if_iter->addr,ETHER_ADDR_LEN);
        eth_header->ether_type = htons(ethertype_ip);

        /* set up ip header */
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
        ip_header->ip_v = 4;
        ip_header->ip_hl = 5; /* in 32-bit words */
        ip_header->ip_tos = 0; 
        ip_header->ip_len = htons(total_len - sizeof(sr_ethernet_hdr_t));
        ip_header->ip_id = 0; /* what id should be put here? */
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = 64;
        ip_header->ip_p = ip_protocol_udp;
        ip_header->ip_src = if_iter->ip;
        ip_header->ip_dst = 0xFFFFFFFF; /* is this 255.255.255.255? */
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));

        /* set up udp header*/
        sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        udp_header->port_dst = htons(520);
        udp_header->port_src = htons(520);
        udp_header->udp_len = htons(sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        
        /* set up rip packet*/
        sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));
        rip_packet->command = 1; /* request */
        /*currently ignore entries field, might not work?*/
        rip_packet->version = 2; 
        rip_packet->unused = 0;

        /* compute udp checksum*/
        udp_header->udp_sum = 0;
        udp_header->udp_sum = udp_cksum(ip_header);

        
        sr_send_packet(sr,buf,total_len,if_iter->name); /* 0 is success, -1 is failure */
        free(buf);
    }

    pthread_mutex_unlock(&(sr->rt_locker));
}

void send_rip_response(struct sr_instance *sr){
    printf("sending RIP response\n");
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_if* if_iter;
    for(if_iter = sr->if_list;if_iter!=NULL;if_iter = if_iter->next){
        /* for each interface, send response */
        
        /* construct ethernet frame */
        uint32_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
        uint8_t* buf = (uint8_t*) malloc(total_len);

        /*  set up ethernet frame header */
        sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) buf;
        memset(eth_header->ether_dhost,255,ETHER_ADDR_LEN); /* Broadcast address, all bits set to 1 */
        memcpy(eth_header->ether_shost,if_iter->addr,ETHER_ADDR_LEN);
        eth_header->ether_type = htons(ethertype_ip);

        /* set up ip header */
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
        ip_header->ip_v = 4;
        ip_header->ip_hl = 5; /* in 32-bit words */
        ip_header->ip_tos = 0; 
        ip_header->ip_len = htons(total_len - sizeof(sr_ethernet_hdr_t));
        ip_header->ip_id = 0; /* what id should be put here? */
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = 64;
        ip_header->ip_p = ip_protocol_udp;
        ip_header->ip_src = if_iter->ip;
        ip_header->ip_dst = 0xFFFFFFFF; /* is this 255.255.255.255? */
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));

        /* set up udp header*/
        sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        udp_header->port_dst = htons(520);
        udp_header->port_src = htons(520);
        udp_header->udp_len = htons(sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        
        /* set up rip packet*/
        sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*) (buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));
        rip_packet->command = 2; /* response */
        rip_packet->version = 2; 
        rip_packet->unused = 0;
        
        /* zero out all entries first*/
        memset(rip_packet->entries,0,MAX_NUM_ENTRIES*20); /*20 bytes per entry*/
        struct sr_rt* rt_walker = 0;
        rt_walker = sr->routing_table;
        int entry_indx = 0;
        while(rt_walker){
            if(rt_walker->metric == INFINITY){
                /* Ignore entries with INFINITY metric since that means invalid entry */
                rt_walker = rt_walker->next;
                continue;
            }
            if(entry_indx >= MAX_NUM_ENTRIES){
                break;
            }

            /* loop through routing table and fill in entries to rip packet*/
            rip_packet->entries[entry_indx].afi = htons(2);/*2 for ip*/
            rip_packet->entries[entry_indx].address = rt_walker->dest.s_addr;
            rip_packet->entries[entry_indx].mask = rt_walker->mask.s_addr;
            rip_packet->entries[entry_indx].next_hop = rt_walker->gw.s_addr;
            /*split horizon w/ poison reverse*/
            if(strcmp(rt_walker->interface, if_iter->name) == 0){
                /* if in an entry, the next hop is the receiving neighbor, set it to infinity(poison the route)*/
                
                /* since we can't get receiving neighbor, 
                 * we assume receiving neighbor and sending 
                 * interface belong to the same subnetwork (need to double check this logic)
                 */
                rip_packet->entries[entry_indx].metric = htonl(INFINITY);
            }else{
                rip_packet->entries[entry_indx].metric = htonl(rt_walker->metric);
            }
            /* ignore tag field for now?*/

            rt_walker = rt_walker->next;
            entry_indx++;
        }

        /* compute udp checksum*/
        udp_header->udp_sum = 0;
        udp_header->udp_sum = udp_cksum(ip_header);

        
        sr_send_packet(sr,buf,total_len,if_iter->name); /* 0 is success, -1 is failure */
        free(buf);

        
    }

    pthread_mutex_unlock(&(sr->rt_locker));
}

void update_route_table(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
    /*printf("receive rip response from interface:%s\n",interface);*/
    pthread_mutex_lock(&(sr->rt_locker));
    sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
    uint32_t sending_interface_ip = ip_header->ip_src; /* need to use ntohl or not?*/

    int entry_index = 0;
    int table_changed = 0;
    /* Iterate through non-empty routing entries in packet */
    while(entry_index<MAX_NUM_ENTRIES && rip_packet->entries[entry_index].afi!=0){ /*assuming valid entry afi field is 2*/
        /*Should print out the address for the entry index
         struct in_addr addr;
            addr.s_addr = rip_packet->entries[entry_index].address;
         printf("received entry Index: %d ||| dest Address: %s\n", entry_index, inet_ntoa(addr));*/

        /*Add one to the metric to compare against infinity*/
        uint32_t received_metric = ntohl(rip_packet->entries[entry_index].metric)+1;

        int metric =  received_metric<INFINITY? received_metric : INFINITY; /*FIX!!!!MIN(received_metric+1, INFINITY)*/

        int found = 0; /*Boolean to check if entry is in routing table*/
        
        struct sr_rt* rt_iter;
        /*Check if entry is in routing table by iterating through tbale and comparing address*/
        for(rt_iter = sr->routing_table;rt_iter!=NULL;rt_iter=rt_iter->next){
            if((rt_iter->dest.s_addr & rt_iter->mask.s_addr) == (rip_packet->entries[entry_index].address & rip_packet->entries[entry_index].mask)){
                found = 1;
                /* contain entry but could be invalid*/
                if(rt_iter->metric!=INFINITY){
                    /*valid*/
                    if(sending_interface_ip==rt_iter->gw.s_addr){
                        /* the packet is from same router as existing entry*/
                        /* MARK TABLE CHAGNED??*/
                        if(rt_iter->metric!=metric)
                            table_changed = 1;
                        /*printf("update_route_table: packet from same router as existing entry\n");
                        printf("rt_iter->metric before: %d\n",rt_iter->metric);*/
                        rt_iter->metric = metric;
                        /*printf("rt_iter->metric after: %d\n",rt_iter->metric);*/
                        rt_iter->updated_time = time(NULL);

                        
                    }else{
                        /* compare the metric and the current metric in this entry. If 
                            metric < current metric in routing table, updating all the information in the
                            routing entry */
                        if(metric<rt_iter->metric){
                            printf("update_route_table: packet from different router than existing entry, with smaller metric\n");
                            rt_iter->metric = metric;
                            rt_iter->gw.s_addr = sending_interface_ip;
                            rt_iter->mask.s_addr = rip_packet->entries[entry_index].mask;
                            rt_iter->updated_time = time(NULL);
                            strncpy(rt_iter->interface,interface,sr_IFACE_NAMELEN); 
                            table_changed = 1;
                        }
                    }
                }else{
                    /* Not existing (not valid - equivalent to not existing - add all)*/
                    printf("update_route_table: table does not contain entry, add it\n");
                    rt_iter->metric = metric;
                    rt_iter->gw.s_addr = sending_interface_ip;
                    rt_iter->mask.s_addr = rip_packet->entries[entry_index].mask;
                    rt_iter->updated_time = time(NULL);
                    strncpy(rt_iter->interface,interface,sr_IFACE_NAMELEN);
                    table_changed = 1;
                }
                
                break;
            }
        }

        /*Not existing (even entry does not exist - add all) */
        if(found == 0 ){

            struct in_addr dest_addr;
            struct in_addr gw_addr;
            struct in_addr mask_addr;
            dest_addr.s_addr = rip_packet->entries[entry_index].address;
            gw_addr.s_addr = sending_interface_ip;
            mask_addr.s_addr = rip_packet->entries[entry_index].mask;
            sr_add_rt_entry(sr, dest_addr , gw_addr , mask_addr, metric , interface);
            table_changed = 1;
            printf("New Routing Table : \n");
            sr_print_routing_table(sr); 
            printf("\n");
        }
        
        entry_index++;
    }

    /* send rip response if routing table changes*/
    if(table_changed == 1){
        printf("table changed..\n");
        send_rip_response(sr);
    }

    pthread_mutex_unlock(&(sr->rt_locker));
}