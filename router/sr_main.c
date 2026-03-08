/*-----------------------------------------------------------------------------
 * File: sr_main.c
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 * Description:
 *
 * Driver file for sr
 *
 *---------------------------------------------------------------------------*/

#ifdef _SOLARIS_
#define __EXTENSIONS__
#endif /* _SOLARIS_ */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef _LINUX_
#include <getopt.h>
#endif /* _LINUX_ */

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_rt.h"

extern char* optarg;

/*-----------------------------------------------------------------------------
 *---------------------------------------------------------------------------*/

#define VERSION_INFO "VNS sr stub code revised 2009-10-14 (rev 0.20)"
#define DEFAULT_PORT 8888
#define DEFAULT_HOST "vrhost"
#define DEFAULT_SERVER "localhost"
#define DEFAULT_RTABLE "rtable"
#define DEFAULT_TOPO 0

static void usage(char* );
static void sr_init_instance(struct sr_instance* );
static void sr_destroy_instance(struct sr_instance* );
static void sr_set_user(struct sr_instance* );
static void sr_load_rt_wrap(struct sr_instance* sr, char* rtable);

/*-----------------------------------------------------------------------------
 *---------------------------------------------------------------------------*/

int main(int argc, char **argv)
{
    int c;
    char *host   = DEFAULT_HOST;
    char *user = 0;
    char *server = DEFAULT_SERVER;
    char *rtable = DEFAULT_RTABLE;
    char *template = NULL;
    unsigned int port = DEFAULT_PORT;
    unsigned int topo = DEFAULT_TOPO;
    char *logfile = 0;
    struct sr_instance sr;

    printf("Using %s\n", VERSION_INFO);

    return 0;
}/* -- main -- */

/*-----------------------------------------------------------------------------
 * Method: usage(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

static void usage(char* argv0)
{
    printf("Simple Router Client\n");
    printf("Format: %s [-h] [-v host] [-s server] [-p port] \n",argv0);
    printf("           [-T template_name] [-u username] \n");
    printf("           [-t topo id] [-r routing table] \n");
    printf("           [-l log file] \n");
    printf("   defaults server=%s port=%d host=%s  \n",
            DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_HOST );
} /* -- usage -- */

/*-----------------------------------------------------------------------------
 * Method: sr_set_user(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

void sr_set_user(struct sr_instance* sr)
{
    uid_t uid = getuid();
    struct passwd* pw = 0;

} /* -- sr_set_user -- */

/*-----------------------------------------------------------------------------
 * Method: sr_destroy_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_destroy_instance(struct sr_instance* sr)
{
} /* -- sr_destroy_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_init_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_init_instance(struct sr_instance* sr)
{
} /* -- sr_init_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_verify_routing_table()
 * Scope: Global
 *
 * make sure the routing table is consistent with the interface list by
 * verifying that all interfaces used in the routing table actually exist
 * in the hardware.
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/

int sr_verify_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;
    struct sr_if* if_walker = 0;
    int ret = 0;

} /* -- sr_verify_routing_table -- */

static void sr_load_rt_wrap(struct sr_instance* sr, char* rtable) {
    
}
