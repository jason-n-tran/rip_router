/*-----------------------------------------------------------------------------
 * file:  sr_inface.
 *
 * Description:
 *
 * Data structures and methods for handling interfaces
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _DARWIN_
#include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_router.h"

/*--------------------------------------------------------------------- 
 * Method: sr_get_interface
 * Scope: Global
 *
 * Given an interface name return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    return 0;
} /* -- sr_get_interface -- */

/*--------------------------------------------------------------------- 
 * Method: sr_add_interface(..)
 * Scope: Global
 *
 * Add and interface to the router's list
 *
 *---------------------------------------------------------------------*/
void sr_add_interface_status(struct sr_instance* sr, const char* name){
    struct sr_if_status_cache* if_cache_walker = 0;
    
}

void sr_update_interface_status(struct sr_instance* sr, uint32_t status, const char* name){
    struct sr_if_status_cache* if_cache_walker = sr->if_cache;
    
}

void sr_add_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

} /* -- sr_add_interface -- */ 

/*--------------------------------------------------------------------- 
 * Method: sr_sat_ether_addr(..)
 * Scope: Global
 *
 * set the ethernet address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_addr(struct sr_instance* sr, const unsigned char* addr)
{
    struct sr_if* if_walker = 0;

} /* -- sr_set_ether_addr -- */

/*--------------------------------------------------------------------- 
 * Method: sr_set_ether_ip(..)
 * Scope: Global
 *
 * set the IP address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_ip(struct sr_instance* sr, uint32_t ip_nbo)
{
    struct sr_if* if_walker = 0;

} /* -- sr_set_ether_ip -- */


void sr_set_ether_mask(struct sr_instance* sr, uint32_t mask_nbo)
{
    struct sr_if* if_walker = 0;

} /* -- sr_set_ether_ip -- */



uint32_t sr_obtain_interface_status(struct sr_instance* sr, const char* name){
    struct sr_if_status_cache* if_cache_walker = sr->if_cache;
    
    return 0;
}

/*--------------------------------------------------------------------- 
 * Method: sr_print_if_list(..)
 * Scope: Global
 *
 * print out the list of interfaces to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if_list(struct sr_instance* sr)
{
    struct sr_if* if_walker = 0;

} /* -- sr_print_if_list -- */

/*--------------------------------------------------------------------- 
 * Method: sr_print_if(..)
 * Scope: Global
 *
 * print out a single interface to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if(struct sr_if* iface)
{
    struct in_addr ip_addr;
    struct in_addr ip_mask;
    
} /* -- sr_print_if -- */
