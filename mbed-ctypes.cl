;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Generated from ctypes.c, do not edit
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(in-package mbedtls)


(warn "char is signed")

(defctype size_t :unsigned-long)

(defconstant EINTR 4)

(defconstant _POSIX_C_SOURCE 200809)

(defconstant INET_ADDRSTRLEN 16)
(defconstant INET6_ADDRSTRLEN 46)

(defconstant TCP_NODELAY 1)
(defconstant IPPROTO_TCP 6)
(defconstant AF_INET 2)
(defconstant AF_INET6 10)

(defconstant POLLIN 1)
(defconstant POLLOUT 4)

(defconstant POLLERR 8)
(defconstant POLLHUP 16)
(defconstant POLLNVAL 32)

(defcstruct pollfd (fd :int) (events :short) (revents :short))

(defcstruct (mbedtls_ssl_context :size 456))
(defcstruct (mbedtls_ssl_config :size 376))
(defcstruct (mbedtls_ssl_session :size 152))
(defcstruct (mbedtls_ssl_cache_context :size 64))

(defcstruct (mbedtls_md_context_t :size 24))

(defcstruct mbedtls_net_context (fd :int))

(defcstruct (mbedtls_x509_crt :size 552))
(defcstruct (mbedtls_x509_crt :size 552)
  (next (:pointer (:struct mbedtls_x509_crt)) :offset 544))
(defcstruct (mbedtls_x509_crl :size 416))
(defcstruct (mbedtls_pk_context :size 16))
(defcstruct (mbedtls_pk_info_t :size 96))
(defcstruct (mbedtls_pk_type_t :size 4))

(defcstruct (mbedtls_entropy_context :size 37960))

(defcstruct (mbedtls_ctr_drbg_context :size 392))

