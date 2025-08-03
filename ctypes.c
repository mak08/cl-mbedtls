/*
 * Description  Extract info from SSL headers  
 * Author       Michael Kappert 2015
 * Last Modified <michael 2025-07-27 16:44:58>
 */


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <poll.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"


int main () {
  FILE *fp;

  // fprintf(stdout, "test_srv_crt: %lu\n", strlen(mbedtls_test_srv_crt));

  ////////////////////////////////////////////////////////////////////////////////
  // Create definitions

  fp = fopen("mbed-ctypes.cl", "w");  

  ////////////////////////////////////////////////////////////////////////////////
  // Write header
  fprintf(fp, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
  fprintf(fp, ";;; Generated from ctypes.c, do not edit\n");
  fprintf(fp, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
  fprintf(fp, "\n");
  fprintf(fp, "(in-package mbedtls)\n");
  fprintf(fp, "\n");
  fprintf(fp, "\n");
  
  // Test signedness of char
  //   char is unsigned on ARM and unsigned *char and char* are used interchangeably in the mbedtls source.
  //   Not sure if this matters.
  char c = -1;
  if ( c == -1 ) 
	{
	  fprintf(stdout, "char is signed\n");
	  fprintf(fp, "%s\n", "(warn \"char is signed\")");
	}
  else
	{
	  fprintf(stdout, "char is unsigned\n");
	}

  ////////////////////////////////////////////////////////////////////////////////
  // size_t
  fprintf(fp, "\n");
  if (sizeof(size_t) == sizeof(unsigned int)) 
	{ 
	  fprintf(fp, "(defctype size_t :unsigned-int)\n");
	}
  else if (sizeof(size_t) == sizeof(unsigned long)) 
	{
	  fprintf(fp, "(defctype size_t :unsigned-long)\n");
	}
  else
	{
	  fprintf(fp, "(defctype size_t :|Fixme - could not determine size of size_t|)\n");
	}

  ////////////////////////////////////////////////////////////////////////////////
  // ERRNO
  fprintf(fp, "\n");
  fprintf(fp, "(defconstant EINTR %i)\n", EINTR);  
 
  ////////////////////////////////////////////////////////////////////////////////
  // Posix Compliance
  fprintf(fp, "\n");
  fprintf(fp, "(defconstant _POSIX_C_SOURCE %lu)\n", _POSIX_C_SOURCE);

  ////////////////////////////////////////////////////////////////////////////////
  // Socket info

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant INET_ADDRSTRLEN %i)\n", INET_ADDRSTRLEN);
  fprintf(fp, "(defconstant INET6_ADDRSTRLEN %i)\n", INET6_ADDRSTRLEN);

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant TCP_NODELAY %i)\n", TCP_NODELAY);
  fprintf(fp, "(defconstant TCP_KEEPALIVE_TIME %i)\n", TCP_KEEPIDLE);
  fprintf(fp, "(defconstant TCP_KEEPALIVE_INTVL %i)\n", TCP_KEEPINTVL);
  fprintf(fp, "(defconstant TCP_KEEPALIVE_PROBES %i)\n", TCP_KEEPCNT);
  fprintf(fp, "(defconstant SOL_SOCKET %i)\n", SOL_SOCKET);
  fprintf(fp, "(defconstant SO_KEEPALIVE %i)\n", SO_KEEPALIVE);
  fprintf(fp, "(defconstant IPPROTO_TCP %i)\n", IPPROTO_TCP);
  fprintf(fp, "(defconstant AF_INET %i)\n", AF_INET);
  fprintf(fp, "(defconstant AF_INET6 %i)\n", AF_INET6);


  fprintf(fp, "\n");
  fprintf(fp, "(defconstant POLLIN %i)\n", POLLIN);
  fprintf(fp, "(defconstant POLLOUT %i)\n", POLLOUT);

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant POLLERR %i)\n", POLLERR);
  fprintf(fp, "(defconstant POLLHUP %i)\n", POLLHUP);
  fprintf(fp, "(defconstant POLLNVAL %i)\n", POLLNVAL);

  fprintf(fp, "\n");
  // fprintf(fp, "(defcstruct (pollfd :size %lu))\n", sizeof(struct pollfd));
  fprintf(fp, "(defcstruct pollfd (fd :int) (events :short) (revents :short))\n");

  ////////////////////////////////////////////////////////////////////////////////
  // mbedTLS structure sizes (for memory allocation)
  fprintf(fp, "\n");

  fprintf(fp, "(defcstruct (mbedtls_ssl_context :size %lu))\n", sizeof(mbedtls_ssl_context));
  fprintf(fp, "(defcstruct (mbedtls_ssl_config :size %lu))\n", sizeof(mbedtls_ssl_config));
  fprintf(fp, "(defcstruct (mbedtls_ssl_session :size %lu))\n", sizeof(mbedtls_ssl_session));
  fprintf(fp, "(defcstruct (mbedtls_ssl_cache_context :size %lu))\n", sizeof(mbedtls_ssl_cache_context));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_md_context_t :size %lu))\n", sizeof(mbedtls_md_context_t));
  
  fprintf(fp, "\n");
  // fprintf(fp, "(defcstruct (mbedtls_net_context :size %lu))\n", sizeof(mbedtls_net_context));
  fprintf(fp, "(defcstruct mbedtls_net_context (fd :int))\n");

  fprintf(fp, "\n");
  fprintf(stdout, "Offsetof(mbedtls_x509_crt, next) = %lu\n", offsetof(mbedtls_x509_crt, next));
  size_t offset = offsetof(mbedtls_x509_crt, next);
  fprintf(fp, "(defcstruct (mbedtls_x509_crt :size %lu))\n", sizeof(mbedtls_x509_crt));
  fprintf(fp, "(defcstruct (mbedtls_x509_crt :size %lu)\n\
  (next (:pointer (:struct mbedtls_x509_crt)) :offset %lu))\n", sizeof(mbedtls_x509_crt), offset);
  fprintf(fp, "(defcstruct (mbedtls_x509_crl :size %lu))\n", sizeof(mbedtls_x509_crl));
  fprintf(fp, "(defcstruct (mbedtls_pk_context :size %lu))\n", sizeof(mbedtls_pk_context));
  //   fprintf(fp, "(defcstruct (mbedtls_pk_info_t :size %lu))\n", sizeof(mbedtls_pk_info_t));
  fprintf(fp, "(defcstruct (mbedtls_pk_type_t :size %lu))\n", sizeof(mbedtls_pk_type_t));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_entropy_context :size %lu))\n", sizeof(mbedtls_entropy_context));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_ctr_drbg_context :size %lu))\n", sizeof(mbedtls_ctr_drbg_context));

  fprintf(fp, "\n");
  fclose(fp);

  return 0;
}
