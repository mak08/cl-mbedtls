/*
 * Description  Predefined mbedTLS callbacks
 * Author       Michael Kappert 2015
 * Last Modified <michael 2016-02-09 20:08:54>
 */

#include "ssl.h"
#include "net.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "ssl_cache.h"

////////////////////////////////////////////////////////////////////////////////
///    Some mbedTLS functions (that we call from Lisp) require callbacks as 
/// mandatory arguments but suitable implementations are provided by mbedTLS 
/// itself. 
///    Instead creating a cfun for the mbedTLS callback calling it via a trampoline,
/// we just pass function pointers to the C functions.
/// This file declares variables holding the function pointers.

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

void ( *my_debug_function ) (void *, int, const char *, int,   const char *) = my_debug;



// net.h
int ( *net_send_function ) (void *, const unsigned char *, size_t) = &mbedtls_net_send;
int ( *net_recv_function ) (void *, unsigned char *, size_t)       = &mbedtls_net_recv;
int ( *net_recv_timeout_function ) (void *, unsigned char *, size_t, uint32_t) = mbedtls_net_recv_timeout;

// void *p_bio;                /*!< context for I/O operations   */

// entropy.h
int ( *mbedtls_entropy_func_function ) (void *data, unsigned char *output, size_t len ) = mbedtls_entropy_func;

// ctr_drbg.h
int ( *mbedtls_ctr_drbg_random_function ) (void *p_rng, unsigned char *output, size_t output_len ) = mbedtls_ctr_drbg_random;

// ssl_cache.h
int ( *mbedtls_ssl_cache_get_function ) (void *, mbedtls_ssl_session *) = mbedtls_ssl_cache_get;
int ( *mbedtls_ssl_cache_set_function ) (void *, const mbedtls_ssl_session *) = mbedtls_ssl_cache_set;

