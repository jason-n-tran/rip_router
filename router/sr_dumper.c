#include <sys/time.h>
#include <sys/types.h>

#include <stdio.h>
#include "sr_dumper.h"

static void
sf_write_header(FILE *fp, int linktype, int thiszone, int snaplen)
{
        struct pcap_file_header hdr;
}

/*
 * Initialize so that sf_write_header() will output to the file named 'fname'.
 */
FILE *
sr_dump_open(const char *fname, int thiszone, int snaplen)
{       
  
}

/*
 * Output a packet to the initialized dump file.
 */
void
sr_dump(FILE *fp, const struct pcap_pkthdr *h, const unsigned char *sp)
{
        struct pcap_sf_pkthdr sf_hdr;
}

void
sr_dump_close(FILE *fp)
{
  fclose(fp);
}

