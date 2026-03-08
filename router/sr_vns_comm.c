/*-----------------------------------------------------------------------------
 * File: sr_vns_comm.c
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sha1.h"
#include "sr_utils.h"
#include "vnscommand.h"

static void sr_log_packet(struct sr_instance* , uint8_t* , int );
static int  sr_arp_req_not_for_us(struct sr_instance* sr,
                                  uint8_t * packet /* lent */,
                                  unsigned int len,
                                  char* interface  /* lent */);
int sr_read_from_server_expect(struct sr_instance* sr /* borrowed */, int expected_cmd);

/*-----------------------------------------------------------------------------
 * Method: sr_session_closed_help(..)
 *
 * Provide debugging hints if VNS closes session
 *
 *----------------------------------------------------------------------------*/
static void sr_session_closed_help()
{
}

/*-----------------------------------------------------------------------------
 * Method: sr_connect_to_server()
 * Scope: Global
 *
 * Connect to the virtual server
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/
int sr_connect_to_server(struct sr_instance* sr,unsigned short port,
                         char* server)
{
    struct hostent *hp;
    c_open command;
    c_open_template ot;
    char* buf;
    uint32_t buf_len;

    return 0;
} /* -- sr_connect_to_server -- */



/*-----------------------------------------------------------------------------
 * Method: sr_handle_hwinfo(..)
 * scope: global
 *
 *
 * Read, from the server, the hardware information for the reserved host.
 *
 *---------------------------------------------------------------------------*/

int sr_handle_hwinfo(struct sr_instance* sr, c_hwinfo* hwinfo)
{
    int num_entries;
    int i = 0;

} /* -- sr_handle_hwinfo -- */

int sr_handle_rtable(struct sr_instance* sr, c_rtable* rtable) {
    
}

int sr_handle_auth_request(struct sr_instance* sr, c_auth_request* req) {
#define AUTH_KEY_LEN 64
#define SHA1_LEN 20
    char auth_key[AUTH_KEY_LEN+1];
    FILE* fp;
    SHA1Context sha1;
    c_auth_reply* ar;
    char* buf;
    int len, len_username, i, ret;

}

int sr_handle_auth_status(struct sr_instance* sr, c_auth_status* status) {
    
}

/*-----------------------------------------------------------------------------
 * Method: sr_read_from_server(..)
 * Scope: global
 *
 * Houses main while loop for communicating with the virtual router server.
 *
 *---------------------------------------------------------------------------*/

int sr_read_from_server(struct sr_instance* sr /* borrowed */)
{
    return sr_read_from_server_expect(sr, 0);
}

int sr_read_from_server_expect(struct sr_instance* sr /* borrowed */, int expected_cmd)
{
    
    int command, len;
    unsigned char *buf = 0;
    c_packet_ethernet_header* sr_pkt = 0;
    int ret = 0, bytes_read = 0;

}/* -- sr_read_from_server -- */

/*-----------------------------------------------------------------------------
 * Method: sr_ether_addrs_match_interface(..)
 * Scope: Local
 *
 * Make sure ethernet addresses are sane so we don't muck uo the system.
 *
 *----------------------------------------------------------------------------*/

static int
sr_ether_addrs_match_interface( struct sr_instance* sr, /* borrowed */
                                uint8_t* buf, /* borrowed */
                                const char* name /* borrowed */ )
{
    struct sr_ethernet_hdr* ether_hdr = 0;
    struct sr_if* iface = 0;

    return 1;

} /* -- sr_ether_addrs_match_interface -- */

/*-----------------------------------------------------------------------------
 * Method: sr_send_packet(..)
 * Scope: Global
 *
 * Send a packet (ethernet header included!) of length 'len' to the server
 * to be injected onto the wire.
 *
 *---------------------------------------------------------------------------*/

int sr_send_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
    c_packet_header *sr_pkt;
    unsigned int total_len =  len + (sizeof(c_packet_header));

    return 0;
} /* -- sr_send_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_log_packet()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

void sr_log_packet(struct sr_instance* sr, uint8_t* buf, int len )
{
    struct pcap_pkthdr h;
    int size;

} /* -- sr_log_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_arp_req_not_for_us()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

int  sr_arp_req_not_for_us(struct sr_instance* sr,
                           uint8_t * packet /* lent */,
                           unsigned int len,
                           char* interface  /* lent */)
{
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;
    struct sr_arp_hdr*       a_hdr = 0;

    return 0;
} /* -- sr_arp_req_not_for_us -- */
