/**
  ******************************************************************************
  * File Name       : net_sockets.c.h
  * Description     : TCP/IP or UDP/IP networking functions implementation based
                    on LwIP API see the file "mbedTLS/library/net_socket_template.c"
                    for the standard implmentation
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Ultimate Liberty license
  * SLA0044, the "License"; You may not use this file except in compliance with
  * the License. You may obtain a copy of the License at:
  *                             www.st.com/SLA0044
  *
  ******************************************************************************
  */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <string.h>
#include <stdint.h>
#if defined(MBEDTLS_NET_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#endif

#include "mbedtls/net_sockets.h"

//#include "lwip/dhcp.h"
//#include "lwip/tcpip.h"
//#include "lwip/netdb.h"
//#include "lwip/sockets.h"
//
//#include "lwip.h"
//#include "netif/ethernet.h"

//#include "ethernetif.h"
//#include "stm32f2xx_hal.h"

//#include "main.h"
/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN INCLUDE */

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

/* USER CODE END INCLUDE */

static int net_would_block( const mbedtls_net_context *ctx );
/* USER CODE BEGIN VARIABLES */

/* USER CODE END VARIABLES */
/*
 * Initialize LwIP stack and get a dynamic IP address.
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
  /* USER CODE BEGIN 0 */

  /* USER CODE END 0 */
  //MX_LWIP_Init();
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host, const char *port, int proto )
{
  int ret;
  struct addrinfo hints;
  struct addrinfo *list;
  struct addrinfo *current;
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Do name resolution with both IPv6 and IPv4 */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;
  /* USER CODE BEGIN 3 */

  /* USER CODE END 3 */

  if(getaddrinfo(host, port, &hints, &list) != 0)
  {
    return MBEDTLS_ERR_NET_UNKNOWN_HOST;
  }

  /* USER CODE BEGIN 4 */

  /* USER CODE END 4 */

  /* Try the sockaddrs until a connection succeeds */
  ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;

  for( current = list; current != NULL; current = current->ai_next)
  {
    ctx->fd = (int) socket(current->ai_family, current->ai_socktype, current->ai_protocol);
    /* USER CODE BEGIN 5 */

    /* USER CODE END 5 */
    if(ctx->fd < 0)
    {
      ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
      continue;
    }

    /* USER CODE BEGIN 6 */

    /* USER CODE END 6 */

    if(connect(ctx->fd, current->ai_addr, (uint32_t)current->ai_addrlen) == 0)
    {
      ret = 0;
      break;
    }

    /* USER CODE BEGIN 7 */

    /* USER CODE END 7 */

    close( ctx->fd );
    /* USER CODE BEGIN 8 */

    /* USER CODE END 8 */
    ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
  }

  /* USER CODE BEGIN 9 */

  /* USER CODE END 9 */

  freeaddrinfo(list);

  return ret;

}

/*
 * Create a listening socket on bind_ip:port
 */
int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto )
{
  int ret = 0;
  /* USER CODE BEGIN 10 */
  mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  /* USER CODE END 10 */

  return ret;
}

/*
 * Accept a connection from a remote client
 */
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
  /* USER CODE BEGIN 11 */
  mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  return 0;
  /* USER CODE END 11 */

}

/*
 * Set the socket blocking or non-blocking
 */
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
  /* USER CODE BEGIN 12 */
  //mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  //return 0;
  return( fcntl( ctx->fd, F_SETFL, fcntl( ctx->fd, F_GETFL ) & ~O_NONBLOCK ) );
  /* USER CODE END 12 */
}

int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
  /* USER CODE BEGIN 13 */
  //mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  //return 0;
  return( fcntl( ctx->fd, F_SETFL, fcntl( ctx->fd, F_GETFL ) | O_NONBLOCK ) );
  /* USER CODE END 13 */
}

/*
 * Portable usleep helper
 */
void mbedtls_net_usleep( unsigned long usec )
{
  /* USER CODE BEGIN 14 */
  mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  /* USER CODE END 14 */
}

/*
 * Read at most 'len' characters
 */
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
  int32_t ret;
  int32_t fd = ((mbedtls_net_context *) ctx)->fd;

  if( fd < 0 )
  {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  ret = (int32_t) read( fd, buf, len );

  if( ret < 0 )
  {
    if(net_would_block(ctx) != 0)
    {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if(errno == EPIPE || errno == ECONNRESET)
    {
      return MBEDTLS_ERR_NET_CONN_RESET;
    }

    if(errno == EINTR)
    {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }

    /* USER CODE BEGIN 15 */

    /* USER CODE END 15 */
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }

  return ret;
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf, size_t len,
                              uint32_t timeout )
{
  /* USER CODE BEGIN 16 */
  //mbedtls_printf ("%s() NOT IMPLEMENTED!!\n", __FUNCTION__);
  //return 0;

  int ret;
  struct timeval tv;
  fd_set read_fds;
  int fd = ((mbedtls_net_context *) ctx)->fd;

  if( fd < 0 )
  {
    return( MBEDTLS_ERR_NET_INVALID_CONTEXT );
  }

  FD_ZERO( &read_fds );
  FD_SET( fd, &read_fds );

  tv.tv_sec  = timeout / 1000;
  tv.tv_usec = ( timeout % 1000 ) * 1000;

  ret = select( fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv );

  /* Zero fds ready means we timed out */
  if( ret == 0 )
  {
    return( MBEDTLS_ERR_SSL_TIMEOUT );
  }

  if( ret < 0 )
  {
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)

    if( WSAGetLastError() == WSAEINTR )
    {
      return( MBEDTLS_ERR_SSL_WANT_READ );
    }

#else

    if( errno == EINTR )
    {
      return( MBEDTLS_ERR_SSL_WANT_READ );
    }

#endif

    return( MBEDTLS_ERR_NET_RECV_FAILED );
  }

  /* This call will not block */
  return( mbedtls_net_recv( ctx, buf, len ) );
  /* USER CODE END 16 */
}

static int net_would_block( const mbedtls_net_context *ctx )
{
  /*
   * Never return 'WOULD BLOCK' on a non-blocking socket
   */

  int val = 0;

  if( ( fcntl( ctx->fd, F_GETFL, val) & O_NONBLOCK ) != O_NONBLOCK )
  {
    return( 0 );
  }

  switch( errno )
  {
#if defined EAGAIN

    case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return( 1 );
  }

  return( 0 );
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
  int32_t ret;
  int fd = ((mbedtls_net_context *) ctx)->fd;

  if( fd < 0 )
  {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  ret = (int32_t) write(fd, buf, len);

  if( ret < 0 )
  {
    if(net_would_block(ctx) != 0)
    {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if(errno == EPIPE || errno == ECONNRESET)
    {
      return MBEDTLS_ERR_NET_CONN_RESET;
    }

    if(errno == EINTR)
    {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    /* USER CODE BEGIN 17 */

    /* USER CODE END 17 */
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  return ret;
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
  if( ctx->fd == -1 )
  {
    return;
  }

  /* USER CODE BEGIN 18 */

  /* USER CODE END 18 */
  shutdown( ctx->fd, 2 );
  close( ctx->fd );

  ctx->fd = -1;
}

#endif /* MBEDTLS_NET_C */
