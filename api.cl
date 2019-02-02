;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description   mbedTLS sockets
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2019-02-02 22:46:20>

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; ToDo
;;;  - closing&deallocation of ressources plain/ssl-stream, mbedtls stream
;;;  - get-octets / buffering seems awkward
;;;  - setting the read timeout
;;;  - handling of empty reads
;;;  - set blocking state (of server socket)
;;;  - keepalive support
;;;    - there is currently no way to use distinct timeouts for reading initial request data and
;;;      for subsequent requests on SSL sockets. Ideally, we don't want to wait very long for the first request. 
;;;  - Add support for non-blocking I/O, currently only blocking I/O is supported
;;;  - Check for memory leaks related to SSL initialization
;;;    - Does CFFI free /return values/ of type string automatically?

(declaim (optimize (debug 1) (safety 3) (speed 3)))

(in-package mbedtls)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Conditions

(define-condition located-error (error)
  ((message :accessor error.message :initarg :message :initform "")
   (location :accessor error.location :initarg :location :initform "(not provided)")))

(define-condition %stream-error (error)
  ((stream  :accessor error.stream :initarg :stream :initform "(not provided)")))

(define-condition stream-write-error (located-error %stream-error)
  ()
  (:report (lambda (c s)
             (format s "In function ~a: ~a"
                     (error.location c)
                     (error.message c)))))

(define-condition stream-read-error (located-error %stream-error)
  ((timeout  :accessor error.timeout :initarg :timeout :initform -1))
  (:report (lambda (c s)
             (format s "In function ~a: ~a (timeout ~a)"
                     (error.location c)
                     (error.message c)
                     (error.timeout c)))))

(define-condition stream-empty-read (located-error %stream-error)
  ()
  (:report (lambda (c s)
             (format s "In ~a: zero bytes received on stream ~a"
                     (error.location c)
                     (error.stream c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Macros

(defmacro check-retval (retval &body form)
  (let ((retvar (gensym))
        (rettextvar (gensym)))
  `(let ((,retvar ,@form))
     (cond
       ((eql ,retvar ,retval)
        ,retval)
       (t
        (let ((,rettextvar (mbedtls-strerror ,retvar)))
          (error "~a returned ~a (~a)" ',form ,rettextvar ,retvar)))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Functions

(defgeneric accept (socket-server &key timeout &allow-other-keys))
(defgeneric deallocate (thing))

(defmethod deallocate ((thing null))
  (log2:warning "Deallocating NULL?"))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Streams

(defclass socket-stream ()
  ((socket :reader socket :initarg :socket)
   (peer :reader peer :initarg :peer)
   ;; keepalive read timeout - 30s
   (keepalive :reader keepalive :initarg :keepalive :initform 30000)
   ;; timeout used for other reads - 1s
   (timeout :reader timeout :initarg :timeout :initform 1000)
   ;; Read buffer - there is no write buffer (yet)
   (buffer :accessor buffer :initform (make-array MBEDTLS_SSL_MAX_CONTENT_LEN :element-type '(unsigned-byte 8)) :initarg :buffer)
   (bufpos :accessor bufpos :initform 0)
   (bufsize :accessor bufsize :initform 0)
   (buffer% :reader buffer% :initform (make-cbuffer))))

(defmethod deallocate :after ((stream socket-stream))
  (log2:trace "Deallocating stream buffer")
  (foreign-free (cbuffer-data (buffer% stream))))

(defclass plain-stream (socket-stream)
  ())
(defclass ssl-stream (socket-stream)
  ((raw-socket :reader raw-socket :initarg :raw-socket)
   (ssl-env :reader ssl-env :initarg :ssl-env)))


(defun buffer-exhausted-p (stream)
  (= (bufpos stream) (bufsize stream)))

(defstruct cbuffer
  (data (foreign-alloc :unsigned-char :count MBEDTLS_SSL_MAX_CONTENT_LEN))
  (length MBEDTLS_SSL_MAX_CONTENT_LEN))

(defmethod print-object ((thing socket-stream) stream)
  (format stream "{Peer ~a on socket ~a}"
          (format-ip (peer thing))
          (mem-ref (socket thing) :uint)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Clients

(defun connect (host &key (method :plain) (port (ecase method (:plain "80") (:ssl "443"))))
  (let ((client-socket (foreign-alloc '(:struct mbedtls_net_context)))
        (peer (format () "~a:~a" host port)))
    (mbedtls-net-init client-socket)
    (log2:debug "Connecting to ~a" peer)
    (let ((res
           (mbedtls-net-connect client-socket host port MBEDTLS_NET_PROTO_TCP)))
      (when (< res 0)
        (error 'stream-read-error
               :location "connect"
               :message (mbedtls-error-text res)))
      (log2:debug "connect: Connected to ~a" peer)
      (make-instance 'plain-stream :socket client-socket :peer peer))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Servers

(defclass socket-server ()
  ((server-host :reader server-host :initarg :host)
   (server-port :reader server-port :initarg :port)
   (keepalive :reader keepalive :initarg :keepalive :initform 10000)
   (server-socket :reader server-socket :initarg :socket)))

(defclass plain-socket-server (socket-server)
  ())

(defclass ssl-socket-server (socket-server)
  ((server-cert :reader server-cert :initarg :cert)
   (server-pkey :reader server-pkey :initarg :pkey)
   (entropy-custom :reader entropy-custom :initarg :entropy-custom)
   (debug-function :reader debug-function :initarg :debug-function)
   (debug-threshold :reader debug-threshold :initarg :debug-threshold)))

(defstruct ssl-env ssl config client-fd)
(defstruct ssl-config conf cache entropy ctr-drbg ciphers)

(defparameter *default-ssl-net-send-function*
  ;; *net-send-function*
  (callback net-send)
  "The send function installed by ACCEPT if the send_fn keyword is not used.")

(defparameter *default-ssl-net-recv-function*
  ;; *net-recv-timeout-function*
  (callback net-recv-timeout)
  "The recv function installed by ACCEPT if the recv_fn keyword is not used.
Must accept a timeout argument.")

(defvar *ciphersuites* (get-ciphers))
(defvar *ciphersuite-names* (map 'vector #'mbedtls-ssl-get-ciphersuite-name *ciphersuites*))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; ACCEPT calls are canceled after 1.5s by default.
;;; The SSL ACCEPT method needs more work - eg. handling failed handshakes.

(defparameter *accept-timeout* 1500)

(defvar *thread-id* 0)

(defmacro with-server-connection (((connvar server) &rest keys &key &allow-other-keys) &body body)
  `(let ((,connvar (accept ,server ,@keys))
         (%id% (gensym)))
     (cond (,connvar
            (unwind-protect
                 (progn
                   (log2:debug "WITH-SERVER-CONNECTION ~a: Executing body" %id%)
                   ,@body)
              (log2:debug "WITH-SERVER-CONNECTION ~a: Cleaning up" %id%)
              (close-socket ,connvar)
              (deallocate ,connvar)))
           (t
            (log2:trace "WITH-SERVER-CONNECTION: Accept returned NIL")))))

(defmacro with-server-connection-async (((connvar server) &rest keys &key &allow-other-keys) &body body)
  `(let ((,connvar (accept ,server ,@keys)))
     (cond
       (,connvar
        (let* ((thread-name (create-thread-name))
               (thread (bordeaux-threads:make-thread
                        (lambda ()
                          (unwind-protect
                               (progn
                                 (log2:debug "WITH-SERVER-CONNECTION-ASYNC: Executing body")
                                 ,@body)
                            (log2:debug "WITH-SERVER-CONNECTION-ASYNC: Cleaning up")
                            (close-socket ,connvar)
                            (deallocate ,connvar)))
                        :name thread-name)))
          (log2:debug "WITH-SERVER-CONNECTION: Spawned ~a." thread-name)))
       (t
        (log2:trace "WITH-SERVER-CONNECTION: Accept returned NIL")))))

(defmethod accept ((server plain-socket-server)
                   &key
                     (timeout *accept-timeout*))
  (multiple-value-bind (client-socket peer)
      (%accept server timeout)
    (when client-socket
      (log2:info "Accepted PLAIN connection from peer ~a" peer)
      (make-instance 'plain-stream :socket client-socket :peer peer :keepalive (keepalive server)))))

(defmethod accept ((server ssl-socket-server)
                   &key
                     (timeout *accept-timeout*)
                     (send-fn *default-ssl-net-send-function*)
                     (recv-fn *default-ssl-net-recv-function*))
    (multiple-value-bind (client-socket peer)
        (%accept server timeout)
      (when client-socket
      (log2:info "Accepted SSL connection from peer ~a" peer)
      (let* ((ssl-env (create-ssl-env
                         (server-cert server)
                         (server-pkey server)
                         (entropy-custom server)
                         (debug-function server)
                         (debug-threshold server)))
               (ssl (ssl-env-ssl ssl-env))
               (ssl-stream (make-instance 'ssl-stream
                                          :socket ssl
                                          :raw-socket client-socket
                                          :ssl-env ssl-env
                                          :peer peer
                                          :keepalive (keepalive server))))
          (check-retval 0 (reseed ssl-env))
          (check-retval 0 (mbedtls-ssl-session-reset ssl))
          (mbedtls-ssl-set-bio ssl
                               client-socket
                               send-fn
                               (null-pointer)
                               recv-fn)
          (log2:trace "Performing handshake...")
          (let ((res (loop
                        :for ret = (mbedtls-ssl-handshake ssl)
                        :while (or (eql ret MBEDTLS_ERR_SSL_WANT_READ)
                                   (eql ret MBEDTLS_ERR_SSL_WANT_WRITE))
                        :finally (return ret))))
            (when (< res 0)
              (deallocate ssl-stream)
              (error 'stream-read-error
                     :location "accept ssl"
                     :message (mbedtls-error-text res))))
          (log2:trace "Handshake complete")
          (log2:debug "Connected to ~a" ssl-stream)
          (values ssl-stream)))))

(defun %accept (server timeout)
  (let ((client-socket (foreign-alloc '(:struct mbedtls_net_context))))
    (mbedtls-net-init client-socket)
    (log2:trace "accept: Waiting for a remote connection ...")
    (multiple-value-bind (res peer)
        ;; Use *accept-timeout* to allow the server loop to exit after a QUIT command
        (mbedtls-net-accept (server-socket server) client-socket :timeout timeout)
      (cond
        ((null res)
         ;; mbedtls-net-accept returns NIL if polling fails and accept was not called 
         (foreign-free client-socket)
         (values nil))
        ((< res 0)
         (foreign-free client-socket)
         (error 'stream-read-error
                :location "%accept"
                :message (mbedtls-error-text res)))
        (t
         (log2:trace "Connected to ~a~%" (format-ip peer))
         (values client-socket peer))))))

(defun reseed (ssl-env)
  (mbedtls-ctr-drbg-reseed (ssl-config-ctr-drbg
                            (ssl-env-config ssl-env))
                           "parent"
                           6))
  
(defmethod deallocate ((plain-stream plain-stream))
  (foreign-free (socket plain-stream)))

(defmethod deallocate ((ssl-stream ssl-stream))
  (foreign-free (raw-socket ssl-stream))
  (deallocate (ssl-env ssl-stream)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 

(defun create-plain-socket-server (host port
                                   &key
                                     (keepalive 10000)
                                     (nodelay t)
                                     (debug-level 0))
  (let* ((server-socket (foreign-alloc '(:struct mbedtls_net_context)))
         (res (mbedtls-net-bind server-socket host port MBEDTLS_NET_PROTO_TCP)))
    (when (< res 0)
      (error 'stream-read-error
             :location "create-plain-socket-server"
             :message (mbedtls-error-text res)))
    (let ((server 
           (make-instance 'plain-socket-server
                          :host host
                          :port port
                          :socket server-socket
                          :keepalive keepalive)))
      (when nodelay
        (check-retval 0
          (with-foreign-object (nodelay :int)
            (setf (mem-ref nodelay :int) -1)
            (log2:debug "Socket: ~a" (mem-ref server-socket :int))
            (setsockopt (mem-aref server-socket :int) IPPROTO_TCP TCP_NODELAY nodelay 4))))
      (log2:info "HTTP Server listening at ~a:~a~%" host port)
      server)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 

(defun create-ssl-socket-server (host port
                                 &key
                                   (server-cert "/home/michael/certs/mbedTLS/localhost_cert.pem")
                                   (server-key "/home/michael/certs/mbedTLS/localhost_key.pem")
                                   (server-key-pw "")
                                   (keepalive 10000)
                                   (nodelay t)
                                   (entropy-custom "SSL_Server")
                                   (debug-function *my-debug-function*)
                                   (debug-level 0))
  (let* ((cert (init-cert-chain server-cert))
         (pkey (load-private-key server-key server-key-pw))
         (server-socket (foreign-alloc '(:struct mbedtls_net_context)))
         (res (progn
                (mbedtls-net-init server-socket)
                (mbedtls-net-bind server-socket host port MBEDTLS_NET_PROTO_TCP))))
    (when (< res 0)
      (error 'stream-read-error
             :location "create-ssl-socket-server"
             :message (mbedtls-error-text res)))
    (when nodelay
      (check-retval 0
        (with-foreign-object (nodelay :int)
          (setf (mem-ref nodelay :int) -1)
          (log2:debug "Socket: ~a" (mem-ref server-socket :int))
          (setsockopt (mem-aref server-socket :int) IPPROTO_TCP TCP_NODELAY nodelay 4))))
    (let ((server
           (make-instance 'ssl-socket-server
                          :host host
                          :port port
                          :socket server-socket
                          :keepalive keepalive
                          :cert cert
                          :pkey pkey
                          :entropy-custom entropy-custom
                          :debug-function debug-function
                          :debug-threshold debug-level)))
      (log2:info "HTTPS Server listening at ~a:~a~%" host port)
      server)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Is this still needed?
(defmethod initialize-instance :after ((thing socket-stream) &rest initargs &key &allow-other-keys)
  (log2:debug "Initializing buffer for ~a" thing))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; API function

(defgeneric get-line (stream &key timeout))

(defmethod get-line ((stream socket-stream) &key (timeout nil))
  ;; Get CRLF terminated line from stream octets buffer;
  ;; Convert to string assuming ASCII encoding
  (when (buffer-exhausted-p stream)
    (refresh-buffer stream :timeout timeout))
  (when (< (bufpos stream) (length (buffer stream)))
    (let ((nextpos (position 13 (buffer stream) :start (bufpos stream))))
      (when nextpos
        (prog1
            (map 'string #'code-char (subseq (buffer stream) (bufpos stream) nextpos))
          (setf (bufpos stream) (1+ nextpos))
          (when (and (< (bufpos stream) (bufsize stream))
                     (eql (aref (buffer stream) (bufpos stream)) 10))
            (incf (bufpos stream))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; API function

(defgeneric get-octets (stream length))

(defmethod get-octets ((stream socket-stream) length)
  (if length
      (read-stream-buffered stream length)
      (subseq (buffer stream) (bufpos stream))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; internal function

(defun read-stream-buffered (stream count)
  (when (buffer-exhausted-p stream)
    (refresh-buffer stream))
  (cond
    ((<= count (- (bufsize stream) (bufpos stream)))
     (prog1
         (values (subseq (buffer stream) (bufpos stream) (+ (bufpos stream) count))
                 count)
       (incf (bufpos stream) count)))
    (t
     (let ((bytes
            (loop
               :for avail = (- (bufsize stream) (bufpos stream)) :then (refresh-buffer stream)
               :for rest = (min count avail)
               :collect (subseq (buffer stream) (bufpos stream) (+ (bufpos stream) rest))
               :do (progn
                     (decf count rest)
                     (incf (bufpos stream) rest))
               :until (or (= count 0)
                          (<= avail 0)))))
       (values
        (apply #'concatenate '(vector (unsigned-byte 8)) bytes)
        count)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; internal function

(defgeneric refresh-buffer (stream &key timeout))

;;; Blocking read with timeout.
;;; There are different timeout mechanisms for plain streams and ssl streams:
;;; - Plain streams simply use mbedtls-net-recv-timeout.
;;; - For SSL streams, a recv_timeout function must be installed with mbedtls-ssl-set-bio.
;;;   By default, *default-ssl-net-recv-function* is used. Data may b read from the SSL 
;;;   stream with mbed-ssl-read, but this function does not have a timeout argument. 
;;;   Instead the timeout must be configured with mbedtls-ssl-conf-read-timeout.

(defmethod refresh-buffer ((stream plain-stream) &key (timeout nil))
  (unless (buffer-exhausted-p stream)
    (log2:error "Refreshing buffer before it was exhausted"))
  (log2:debug "Rebuffering")
  (clear-buffer (cbuffer-data (buffer% stream)) (cbuffer-length (buffer% stream)))
  (let* ((timeout (or timeout (timeout stream)))
         (res
          (mbedtls-net-recv-timeout (socket stream)
                                    (cbuffer-data (buffer% stream))
                                    (cbuffer-length (buffer% stream))
                                    ;; Use the keepalive-timeout if provided.
                                    ;; (CALLBACK NET_RECV_TIMEOUT) does the same thing
                                    ;; for SSL (well, almost).)))
                                    timeout)))
    (setf (bufpos stream) 0)
    (setf (bufsize stream) res)
    (cond
      ((< res 0)
       (error 'stream-read-error
              :location "refresh-buffer"
              :message (mbedtls-error-text res)
              :timeout timeout))
      ((= res 0)
       (log2:warning "empty read")
       (error 'stream-empty-read :location "refresh-buffer" :stream stream))
      (t
       (setf (buffer stream)
             (convert-uint8-array-to-lisp (cbuffer-data (buffer% stream)) res))))
    res))

(defmethod refresh-buffer ((stream ssl-stream) &key (timeout nil))
  (unless (buffer-exhausted-p stream)
    (log2:error "Refreshing buffer before it was exhausted"))    
  (log2:debug "Rebuffering")
  (clear-buffer (cbuffer-data (buffer% stream)) (cbuffer-length (buffer% stream)))
  (let ((timeout (or timeout (timeout stream))))

    (log2:debug "refresh-buffer: configure read timeout ~a" timeout)
    (mbedtls-ssl-conf-read-timeout (ssl-config-conf (ssl-env-config (ssl-env stream))) timeout)
    
    (let ((res
           (mbedtls-ssl-read (socket stream)
                             (cbuffer-data (buffer% stream))
                             (cbuffer-length (buffer% stream)))))
      (setf (bufpos stream) 0)
      (setf (bufsize stream) res)
      (cond
        ((< res 0)
         (error 'stream-read-error
                :location "refresh-buffer"
                :message (mbedtls-error-text res)
                :timeout timeout))
        ((= res 0)
         (error 'stream-empty-read :location "refresh-buffer" :stream stream))
        (t
         (setf (buffer stream)
               (convert-uint8-array-to-lisp (cbuffer-data (buffer% stream)) res))))
      res)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defgeneric write-to-stream (stream data))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod write-to-stream ((stream ssl-stream) (data string))
  (loop
     :for k :by MBEDTLS_SSL_MAX_CONTENT_LEN
     :while (< k (length data))
     :do (let* ((chunk (subseq data k  (min (+ k MBEDTLS_SSL_MAX_CONTENT_LEN) (length data)))))
           (with-foreign-string ((buf buflen) chunk)
             (let ((res (mbedtls-ssl-write (socket stream) buf buflen)))
               (unless (eql res buflen)
                 (log2:debug "mbedtls_ssl_write returned ~a" res)
                 (error 'stream-write-error
                        :location "write-to-stream ssl"
                        :message (mbedtls-error-text res)))))))
  (log2:debug "Wrote ~a bytes" (length data))
  (length data))

(defmethod write-to-stream ((stream ssl-stream) (data vector))
  (loop
     :for k :by MBEDTLS_SSL_MAX_CONTENT_LEN
     :while (<  k (length data))
     :do (let ((chunk (subseq data k  (min (+ k MBEDTLS_SSL_MAX_CONTENT_LEN) (length data)))))
           (with-foreign-array (c-chunk chunk :uint8)
             (let ((res
                    (mbedtls-ssl-write (socket stream) c-chunk (length chunk))))
               (unless (eql res (length chunk))
                 (log2:debug "mbedtls_ssl_write returned ~a" res)
                 (error 'stream-write-error
                        :location "write-to-stream ssl"
                        :message (mbedtls-error-text res)))))))
  (log2:debug "Wrote ~a bytes" (length data))
  (length data))

(defmethod write-to-stream ((stream plain-stream) (data string))
  (log2:debug "Writing ~a bytes" (length data))
  (with-foreign-string ((buf buflen) data)
    (let ((res
           (mbedtls-net-send (socket stream) buf buflen)))
      (unless (eql res buflen)
        (error 'stream-write-error
               :location "write-to-stream plain"
               :message (mbedtls-error-text res)))
      (log2:debug "Wrote ~a bytes, returning ~a" (length data) res)
      res)))

(defmethod write-to-stream ((stream plain-stream) (data vector))
  (log2:debug "Writing ~a chars" (length data))
  ;; What does Babel give us?
  ;; (assert (equal (array-element-type data) '(unsigned-byte 8))) 
  (with-foreign-array (c-data data :uint8)
    (let ((res
           (mbedtls-net-send (socket stream) c-data (length data))))
      (unless (eql res (length data))
        (error 'stream-write-error
               :location "write-to-stream plain"
               :message (mbedtls-error-text res)))
      (log2:debug "Wrote ~a chars, returning ~a" (length data) res)
      res)))

(defmethod write-to-stream ((s stream) (data vector))
  (log2:debug "Wrote ~a bytes" (length data))
  (format s "~a" (map 'string #'code-char data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defgeneric close-socket (stream))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod close-socket :before ((socket t))
  (log2:info "Closing connection to peer ~a" (peer socket)))

(defmethod close-socket ((stream ssl-stream))
  (log2:debug "Closing ~a" stream)
  (mbedtls-ssl-close-notify (socket stream))
  (mbedtls-net-free (raw-socket stream)))

(defmethod close-socket ((stream plain-stream))
  (log2:debug "Closing socket connection ~a" stream)
  (mbedtls-net-free (socket stream)))

(defmethod close-socket ((socket socket-server))
  (mbedtls-net-free (server-socket socket)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SSL Server setup

(defun create-ssl-env (cert pkey entropy-custom debug-function debug-threshold)
  (log2:debug "Set up SSL context")
  (let ((ssl (foreign-alloc '(:struct mbedtls_ssl_context)))
        (config (create-config cert pkey entropy-custom debug-function debug-threshold)))
    (mbedtls-ssl-init ssl)
    (check-retval 0
      (mbedtls-ssl-setup ssl (ssl-config-conf config)))
    (log2:debug "SSL context ready")
    (make-ssl-env :ssl ssl :config config)))

(defmethod deallocate ((ssl-env ssl-env))
  (log2:debug "Destroy SSL context")
  (foreign-free (ssl-env-ssl ssl-env))
  (deallocate (ssl-env-config ssl-env)))

(defun create-config (cert pkey entropy-custom debug-function debug-threshold)
  (let* ((conf (foreign-alloc '(:struct mbedtls_ssl_config)))
         (entropy (foreign-alloc '(:struct mbedtls_entropy_context)))
         (ctr-drbg (foreign-alloc '(:struct mbedtls_ctr_drbg_context)))
         (all-ciphersuites *ciphersuites*)
         (ciphersuites (foreign-alloc :int :count (1+ (length all-ciphersuites)))))
    (mbedtls-ssl-config-init conf)
    (mbedtls-entropy-init entropy)
    (mbedtls-ctr-drbg-init ctr-drbg)

    (log2:debug "Configuring session defaults")
     
    (check-retval 0
      (mbedtls-ssl-config-defaults conf
                                   MBEDTLS_SSL_IS_SERVER
                                   MBEDTLS_SSL_TRANSPORT_STREAM
                                   MBEDTLS_SSL_PRESET_DEFAULT))

    ;; This is NOT the keep-alive timeout but the normal read timeout.
    ;; The value SHOULD be taken from (timeout <ssl-stream>) ?!
    (mbedtls-ssl-conf-read-timeout conf 1000)

    (dotimes (i (length all-ciphersuites))
      (setf (mem-aref ciphersuites :int i)
            (aref all-ciphersuites i)))
    (mbedtls-ssl-conf-ciphersuites conf ciphersuites)

    ;; CTR_DRBG initial seeding
    (check-retval 0
      (with-foreign-string (custom entropy-custom)
        ;; Digging deep into ctr_drbg.c reveals that $custom is copied internally,
        ;; it may be stack-allocated here.
        (mbedtls-ctr-drbg-seed ctr-drbg
                               *mbedtls-entropy-func-function*
                               entropy 
                               custom
                               (length entropy-custom))))

    ;; Set the random number generator callback
    (mbedtls-ssl-conf-rng conf *mbedtls-ctr-drbg-random-function* ctr-drbg)

    ;; Set the debug callback
    (mbedtls-ssl-conf-dbg conf debug-function *stdout*)
    (mbedtls-debug-set-threshold debug-threshold)

    ;; Configure certificates
    (check-retval 0
      (mbedtls-ssl-conf-own-cert conf cert pkey))

    ;; Return everything that needs to be references (or freed)
    (make-ssl-config :conf conf :entropy entropy :ctr-drbg ctr-drbg :ciphers ciphersuites)))

(defmethod deallocate ((ssl-config ssl-config))
  (foreign-free (ssl-config-conf ssl-config))
  (foreign-free (ssl-config-entropy ssl-config))
  (foreign-free (ssl-config-ctr-drbg ssl-config))
  (foreign-free (ssl-config-ciphers ssl-config)))
  
(defun init-cert-chain (&optional path)
  (let ((cert (foreign-alloc '(:struct mbedtls_x509_crt))))
    (mbedtls-x509-crt-init cert)
    (when path
      (check-retval 0
        (mbedtls-x509-crt-parse-file cert path)))
    cert))

(defun add-to-cert-chain (chain path)
  (check-retval 0
    (mbedtls-x509-crt-parse-file chain path))
  chain)

(defun load-private-key (path &optional (password ""))
  (let ((pkey (foreign-alloc '(:struct mbedtls_pk_context))))
    (mbedtls-pk-init pkey)
    (check-retval 0
      (mbedtls-pk-parse-keyfile pkey path password))
    pkey))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers

(defgeneric format-ip (address))

(defmethod format-ip ((ip string))
  ip)

(defmethod format-ip ((ip list))
  (format () "<~{~d~^.~}>" ip))

(defun create-thread-name ()
  (format () "handler-~d" (incf *thread-id*)))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
