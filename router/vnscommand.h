/*-----------------------------------------------------------------------------
   File:   vnscommand.h 
  
   Description:
  
   A c-style declaration of commands for the virtual router.
  
  ---------------------------------------------------------------------------*/

#ifndef __VNSCOMMAND_H
#define __VNSCOMMAND_H

#define VNSOPEN       1
#define VNSCLOSE      2
#define VNSPACKET     4
#define VNSBANNER     8
#define VNSHWINFO    16

#define IDSIZE 32

/*-----------------------------------------------------------------------------
                                 BASE
  ---------------------------------------------------------------------------*/

typedef struct
{       
}__attribute__ ((__packed__)) c_base;

/*-----------------------------------------------------------------------------
                                 OPEN
  ---------------------------------------------------------------------------*/

typedef struct 
{
}__attribute__ ((__packed__)) c_open;

/*-----------------------------------------------------------------------------
                                 CLOSE
  ---------------------------------------------------------------------------*/

typedef struct 
{
}__attribute__ ((__packed__)) c_close;

/*-----------------------------------------------------------------------------
                                HWREQUEST 
  ---------------------------------------------------------------------------*/

typedef struct 
{
}__attribute__ ((__packed__)) c_hwrequest;

/*-----------------------------------------------------------------------------
                                 BANNER 
  ---------------------------------------------------------------------------*/

typedef struct 
{
}__attribute__ ((__packed__)) c_banner;

/*-----------------------------------------------------------------------------
                               PACKET (header)
  ---------------------------------------------------------------------------*/


typedef struct
{
}__attribute__ ((__packed__)) c_packet_ethernet_header;

typedef struct
{
}__attribute__ ((__packed__)) c_packet_header;

typedef struct
{
}__attribute__ ((__packed__)) c_hw_entry;

typedef struct
{
}__attribute__ ((__packed__)) c_hwinfo;

/* rtable */
typedef struct
{
}__attribute__ ((__packed__)) c_rtable;

/* open template */
typedef struct {
}__attribute__ ((__packed__)) c_src_filter;

typedef struct
{
}__attribute__ ((__packed__)) c_open_template;

/* authentication request */
typedef struct
{
}__attribute__ ((__packed__)) c_auth_request;

/* authentication reply */
typedef struct
{
}__attribute__ ((__packed__)) c_auth_reply;

/* authentication status (whether or not a reply was accepted) */
typedef struct
{
}__attribute__ ((__packed__)) c_auth_status;


#endif  /* __VNSCOMMAND_H */
