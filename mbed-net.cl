;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2019-01-06 18:45:12>

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Use these as *net-send-function* *net-recv-function* *net-recv-timeout-function*
;;; to trace ssl raw data

(in-package mbedtls)

(defconstant MBEDTLS_ERR_NET_SOCKET_FAILED                     #x-0042) ;  /**< Failed to open a socket. */
(defconstant MBEDTLS_ERR_NET_CONNECT_FAILED                    #x-0044) ;  /**< The connection to the given server / port failed. */
(defconstant MBEDTLS_ERR_NET_BIND_FAILED                       #x-0046) ;  /**< Binding of the socket failed. */
(defconstant MBEDTLS_ERR_NET_LISTEN_FAILED                     #x-0048) ;  /**< Could not listen on the socket. */
(defconstant MBEDTLS_ERR_NET_ACCEPT_FAILED                     #x-004A) ;  /**< Could not accept the incoming connection. */
(defconstant MBEDTLS_ERR_NET_RECV_FAILED                       #x-004C) ;  /**< Reading information from the socket failed. */
(defconstant MBEDTLS_ERR_NET_SEND_FAILED                       #x-004E) ;  /**< Sending information through the socket failed. */
(defconstant MBEDTLS_ERR_NET_CONN_RESET                        #x-0050) ;  /**< Connection was reset by peer. */
(defconstant MBEDTLS_ERR_NET_UNKNOWN_HOST                      #x-0052) ;  /**< Failed to get an IP address for the given hostname. */
(defconstant MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  #x-0043) ;  /**< Buffer is too small to hold the data. */
(defconstant MBEDTLS_ERR_NET_INVALID_CONTEXT                   #x-0045) ;  /**< The context is invalid, eg because it was free()ed. */

(defconstant MBEDTLS_NET_LISTEN_BACKLOG         10 ) ;/**< The backlog that listen() should use. */

(defconstant MBEDTLS_NET_PROTO_TCP 0) ; /**< The TCP transport protocol */
(defconstant MBEDTLS_NET_PROTO_UDP 1) ; /**< The UDP transport protocol */

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Initialize a context
;;                 Just makes the context ready to be used or freed safely.
;;
;; \param ctx      Context to initialize
;;
;; void mbedtls_net_init( mbedtls_net_context *ctx );

(defcfun "mbedtls_net_init" :void (net_context (:pointer (:struct mbedtls_net_context))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Initiate a connection with host:port in the given protocol
;;
;; \param ctx      Socket to use
;; \param host     Host to connect to
;; \param port     Port to connect to
;; \param proto    Protocol: MBEDTLS_NET_PROTO_TCP or MBEDTLS_NET_PROTO_UDP
;;
;; \return         0 if successful, or one of:
;;                      MBEDTLS_ERR_NET_SOCKET_FAILED,
;;                      MBEDTLS_ERR_NET_UNKNOWN_HOST,
;;                      MBEDTLS_ERR_NET_CONNECT_FAILED
;;
;; \note           Sets the socket in connected mode even with UDP.
;;
;; int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host, const char *port, int proto );

(defcfun "mbedtls_net_connect" :int (net_context (:pointer (:struct mbedtls_net_context))) (host :string) (port :string) (proto :int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Create a receiving socket on bind_ip:port in the chosen
;;                 protocol. If bind_ip == NULL, all interfaces are bound.
;;
;; \param ctx      Socket to use
;; \param bind_ip  IP to bind to, can be NULL
;; \param port     Port number to use
;; \param proto    Protocol: MBEDTLS_NET_PROTO_TCP or MBEDTLS_NET_PROTO_UDP
;;
;; \return         0 if successful, or one of:
;;                      MBEDTLS_ERR_NET_SOCKET_FAILED,
;;                      MBEDTLS_ERR_NET_BIND_FAILED,
;;                      MBEDTLS_ERR_NET_LISTEN_FAILED
;;
;; \note           Regardless of the protocol, opens the sockets and binds it.
;;                 In addition, make the socket listening if protocol is TCP.
;;
;; int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto );

(defcfun "mbedtls_net_bind" :int (net_context (:pointer (:struct mbedtls_net_context))) (host :string) (port :string) (proto :int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief           Accept a connection from a remote client
;;
;; \param bind_ctx  Relevant socket
;; \param client_ctx Will contain the connected client socket
;; \param client_ip Will contain the client IP address
;; \param buf_size  Size of the client_ip buffer
;; \param ip_len    Will receive the size of the client IP written
;;
;; \return          0 if successful, or
;;                  MBEDTLS_ERR_NET_ACCEPT_FAILED, or
;;                  MBEDTLS_ERR_NET_BUFFER_TOO_SMALL if buf_size is too small,
;;                  MBEDTLS_ERR_SSL_WANT_READ if bind_fd was set to
;;                  non-blocking and accept() would block.
;;
;; int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
;;                         mbedtls_net_context *client_ctx,
;;                         void *client_ip, size_t buf_size, size_t *ip_len );

(defcfun mbedtls_net_accept
    :int
  (bind_context (:pointer (:struct mbedtls_net_context)))
  (client_context (:pointer (:struct mbedtls_net_context)))
  (client_ip :pointer)
  (buf_size size_t)
  (ip_len (:pointer size_t)))

;; Accept a socket connection. Timeout = nil means no timeout.
(defun mbedtls-net-accept (bind-context client-context &key (timeout 20000))
  (with-foreign-objects
      ((client-ip :int8 4)
       (client-ip-len '(:pointer :int))
       (dest :unsigned-char (1+ INET_ADDRSTRLEN))
       (fds '(:struct pollfd) 1))
    (let ((fd1 fds)
          (sock (foreign-slot-value bind-context '(:struct mbedtls_net_context) 'fd))
          (ready 1))
      (when timeout
        (setf (foreign-slot-value fd1 '(:struct pollfd) 'fd) sock)
        (setf (foreign-slot-value fd1 '(:struct pollfd) 'events) (logior pollin pollout))
        (log2:debug "Polling ~a" sock)
        (tagbody
          :poll
          (setf ready (poll fds 1 timeout))
          (when (and (= ready -1) (= *errno* EINTR))
            (log2:trace "Poll error: ~d ~s, retrying." ready (strerror-r *errno*))
            (go :poll))))
      (case ready
        (0
         ;; Designates a poll timeout
         (log2:trace "Poll timout")
         (values nil t))
        (1
         (let ((ret
                 (mbedtls_net_accept bind-context client-context client-ip 4 client-ip-len)))
           (cond ((not (= ret 0))
                  (error "Socket accept error ~a" (mbedtls-error-text ret)))
                 (t
                  (unless (eql (mem-ref client-ip-len :int) 4)
                    (error "Invalid peer address length ~a" (mem-ref client-ip-len :int)))
                  (let ((ip-p (inet-ntop AF_INET client-ip dest (1+ INET_ADDRSTRLEN))))
                    (when (null ip-p)
                      (let ((msg (strerror-r *errno*)))
                        (log2:error "inet_ntop: ~a" msg)
                        (error msg)))
                    (log2:debug "Client IP: ~a" ip-p)
                    (values ret ip-p))))))
        (otherwise
         (log2:debug "Poll error: Ready=~d, ~s" ready (strerror-r *errno*))
         (values nil t))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Set the socket blocking
;;
;; \param ctx      Socket to set
;;
;; \return         0 if successful, or a non-zero error code
;;
;; int mbedtls_net_set_block( mbedtls_net_context *ctx );

(defcfun "mbedtls_net_set_block" :int (net_contet (:pointer (:struct mbedtls_net_context))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Set the socket non-blocking
;;
;; \param ctx      Socket to set
;;
;; \return         0 if successful, or a non-zero error code
;;
;; int mbedtls_net_set_nonblock( mbedtls_net_context *ctx );

(defcfun "mbedtls_net_set_nonblock" :int (net_contet (:pointer (:struct mbedtls_net_context))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Portable usleep helper
;;
;; \param usec     Amount of microseconds to sleep
;;
;; \note           Real amount of time slept will not be less than
;;                 select()'s timeout granularity (typically, 10ms).
;;
;; void mbedtls_net_usleep( unsigned long usec );

(defcfun "mbedtls_net_usleep" :void (usec :unsigned-long))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Read at most 'len' characters. If no error occurs,
;;                 the actual amount read is returned.
;;
;; \param ctx      Socket
;; \param buf      The buffer to write to
;; \param len      Maximum length of the buffer
;;
;; \return         the number of bytes received,
;;                 or a non-zero error code; with a non-blocking socket,
;;                 MBEDTLS_ERR_SSL_WANT_READ indicates read() would block.
;;
;; int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len );

(defcfun "mbedtls_net_recv" :int (context :pointer) (buffer :string) (len size_t))

(defcallback net-recv :int ((ctx :pointer) (buf (:pointer :unsigned-char)) (len size_t))
  (let ((ret (mbedtls-net-recv ctx buf len)))
    (log2:debug "net-recv -> ~a" ret)
    ret))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Write at most 'len' characters. If no error occurs,
;;                 the actual amount read is returned.
;;
;; \param ctx      Socket
;; \param buf      The buffer to read from
;; \param len      The length of the buffer
;;
;; \return         the number of bytes sent,
;;                 or a non-zero error code; with a non-blocking socket,
;;                 MBEDTLS_ERR_SSL_WANT_WRITE indicates write() would block.
;;
;; int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len );

(defcfun "mbedtls_net_send" :int (context :pointer) (buffer :string) (len size_t))

(defcallback net-send :int ((ctx :pointer) (buf (:pointer :unsigned-char)) (len size_t))
  (let ((ret (mbedtls-net-send ctx buf len)))
    (log2:debug "net-send(~a, ~a, ~a) -> ~a" ctx buf len ret)
    ret))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Read at most 'len' characters, blocking for at most
;;                 'timeout' seconds. If no error occurs, the actual amount
;;                 read is returned.
;;
;; \param ctx      Socket
;; \param buf      The buffer to write to
;; \param len      Maximum length of the buffer
;; \param timeout  Maximum number of milliseconds to wait for data
;;                 0 means no timeout (wait forever)
;;
;; \return         the number of bytes received,
;;                 or a non-zero error code:
;;                 MBEDTLS_ERR_SSL_TIMEOUT if the operation timed out,
;;                 MBEDTLS_ERR_SSL_WANT_READ if interrupted by a signal.
;;
;; \note           This function will block (until data becomes available or
;;                 timeout is reached) even if the socket is set to
;;                 non-blocking. Handling timeouts with non-blocking reads
;;                 requires a different strategy.
;;
;; int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf, size_t len,
;;                       uint32_t timeout );

(defcfun "mbedtls_net_recv_timeout" :int (context :pointer) (buffer :string) (len size_t) (timeout :uint32))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;   This function is installed with mbedtls_ssl_set_bios as the f_recv_timeout
;;; function used in calls to mbedtls_ssl_read().
;;;
;;;   The timeout is configured with mbedtls-ssl-conf-read-timeout
;;; in refresh-buffer.
;;;
;;;   Note that the net_recv_timeout function is called at least twice from
;;; mbedtls_ssl_read - to read the SSL header and then to read the payload.

(defcallback net-recv-timeout :int ((ctx :pointer) (buf (:pointer :unsigned-char)) (len size_t) (timeout :int32))
  (let ((ret
         (mbedtls-net-recv-timeout ctx buf len timeout)))
    (log2:debug "net_recv_timeout(~a, ~a, ~a, ~a) => ~a" ctx buf len timeout ret)
    ret))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          Gracefully shutdown the connection and free associated data
;;
;; \param ctx      The context to free
;;
;; void mbedtls_net_free( mbedtls_net_context *ctx );

(defcfun "mbedtls_net_free" :void (net_context (:pointer (:struct mbedtls_net_context))))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
