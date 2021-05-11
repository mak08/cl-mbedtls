;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2021-05-08 21:42:22>

(in-package mbedtls)


(defconstant MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE   #x-5080) ;  /**< The selected feature is not available. */
(defconstant MBEDTLS_ERR_MD_BAD_INPUT_DATA        #x-5100) ;  /**< Bad input parameters to function. */
(defconstant MBEDTLS_ERR_MD_ALLOC_FAILED          #x-5180) ;  /**< Failed to allocate memory. */
(defconstant MBEDTLS_ERR_MD_FILE_IO_ERROR         #x-5200) ;  /**< Opening or reading of file failed. */
(defconstant MBEDTLS_ERR_MD_HW_ACCEL_FAILED       #x-5280) ;  /**< MD hardware accelerator failed. */


(defconstant MBEDTLS_MD_NONE 0)      ; /**< None. */
(defconstant MBEDTLS_MD_MD2 1)       ; /**< The MD2 message digest. */
(defconstant MBEDTLS_MD_MD4 2)       ; /**< The MD4 message digest. */
(defconstant MBEDTLS_MD_MD5 3)       ; /**< The MD5 message digest. */
(defconstant MBEDTLS_MD_SHA1 4)      ; /**< The SHA-1 message digest. */
(defconstant MBEDTLS_MD_SHA224 5)    ; /**< The SHA-224 message digest. */
(defconstant MBEDTLS_MD_SHA256 6)    ; /**< The SHA-256 message digest. */
(defconstant MBEDTLS_MD_SHA384 7)    ; /**< The SHA-384 message digest. */
(defconstant MBEDTLS_MD_SHA512 8)    ; /**< The SHA-512 message digest. */
(defconstant MBEDTLS_MD_RIPEMD160 9) ; /**< The RIPEMD-160 message digest. */

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  \brief           This function initializes a message-digest context without
;;                   binding it to a particular message-digest algorithm.
;; 
;;                   This function should always be called first. It prepares the
;;                   context for mbedtls_md_setup() for binding it to a
;;                   message-digest algorithm.
;;
;; void mbedtls_md_init( mbedtls_md_context_t *ctx );

(defcfun ("mbedtls_md_init" mbedtls_md_init)
    :void
  (ctx :pointer))

(defun mbedtls-md-init ()
  (let ((ctx (foreign-alloc 'mbedtls_md_context_t)))
    (mbedtls_md_init ctx)
    ctx))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  \brief           This function returns the list of digests supported by the
;;                   generic digest module.
;; 
;;  \return          A statically allocated array of digests. Each element
;;                   in the returned list is an integer belonging to the
;;                   message-digest enumeration #mbedtls_md_type_t.
;;                   The last entry is 0.
;;
;; const int *mbedtls_md_list( void );

(defcfun ("mbedtls_md_list")
    :pointer)

(defun mbedtls-md-list-names ()
  (let ((digests (mbedtls::mbedtls-md-list)))
    (loop 
       :for k :from 0
       :for d = (mem-aref digests :int k)
       :while (> d 0)
       :collect (mbedtls-md-get-name (mbedtls-md-info-from-type d)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  \brief           This function returns the message-digest information
;;                   associated with the given digest type.
;; 
;;  \param md_type   The type of digest to search for.
;; 
;;  \return          The message-digest information associated with \p md_type.
;;  \return          NULL if the associated message-digest information is not found.
;; 
;; const mbedtls_md_info_t *mbedtls_md_info_from_type( mbedtls_md_type_t md_type );

(defcfun "mbedtls_md_info_from_type"
    :pointer
  (md_type :int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief           This function returns the message-digest information
;;                  associated with the given digest name.
;; 
;; \param md_name   The name of the digest to search for.
;; 
;; \return          The message-digest information associated with \p md_name.
;; \return          NULL if the associated message-digest information is not found.
;; 
;; const mbedtls_md_info_t *mbedtls_md_info_from_string( const char *md_name );

(defcfun "mbedtls_md_info_from_string"
    :pointer
  (md_name :string))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief           This function extracts the message-digest name from the
;;                  message-digest information structure.
;; 
;; \param md_info   The information structure of the message-digest algorithm
;;                  to use.
;; 
;; \return          The name of the message digest.
;; 
;; const char *mbedtls_md_get_name( const mbedtls_md_info_t *md_info );

(defcfun "mbedtls_md_get_name"
    :string
  (md_info :pointer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief           This function selects the message digest algorithm to use,
;;                  and allocates internal structures.
;; 
;;                  It should be called after mbedtls_md_init() or
;;                  mbedtls_md_free(). Makes it necessary to call
;;                  mbedtls_md_free() later.
;; 
;; \param ctx       The context to set up.
;; \param md_info   The information structure of the message-digest algorithm
;;                  to use.
;; \param hmac      Defines if HMAC is used. 0: HMAC is not used (saves some memory),
;;                  or non-zero: HMAC is used with this context.
;; 
;; \return          \c 0 on success.
;; \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
;;                  failure.
;; \return          #MBEDTLS_ERR_MD_ALLOC_FAILED on memory-allocation failure.
;; 
;; int mbedtls_md_setup( mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac );

(defcfun "mbedtls_md_setup"
    :int
  (ctx :pointer)
  (md_info :pointer)
  (hmac :int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief           This function clears the internal structure of \p ctx and
;;                  frees any embedded internal structure, but does not free
;;                  \p ctx itself.
;; 
;;                  If you have called mbedtls_md_setup() on \p ctx, you must
;;                  call mbedtls_md_free() when you are no longer using the
;;                  context.
;;                  Calling this function if you have previously
;;                  called mbedtls_md_init() and nothing else is optional.
;;                  You must not call this function if you have not called
;;                  mbedtls_md_init().
;; 
;;; void mbedtls_md_free( mbedtls_md_context_t *ctx );

(defcfun ("mbedtls_md_free" mbedtls_md_free)
    :void
  (ctx :pointer))

(defun mbedtls-md-clear-context (context)
  (mbedtls_md_free context))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; \brief          This function calculates the message-digest of a buffer,
;;                 with respect to a configurable message-digest algorithm
;;                 in a single call.
;; 
;;                 The result is calculated as
;;                 Output = message_digest(input buffer).
;; 
;; \param md_info  The information structure of the message-digest algorithm
;;                 to use.
;; \param input    The buffer holding the data.
;; \param ilen     The length of the input data.
;; \param output   The generic message-digest checksum result.
;; 
;; \return         \c 0 on success.
;; \return         #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
;;                 failure.
;; 
;; int mbedtls_md( const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
;;         unsigned char *output );

(defcfun ("mbedtls_md" mbedtls_md)
    :int
  (md_info :pointer)
  (input :string)
  (ilen :int)
  (output :pointer))

(defparameter *md-ctx*
  (progn
    (log2:info "Initializing md context")
    (mbedtls-md-init)))

(defun mbedtls-md (message &key (method "SHA512") (result-type :bytes))
  (ecase result-type (:bytes) (:chars))
  (let ((info (mbedtls-md-info-from-string method))
        (length (cond
                  ((string= method "SHA512") 64)
                  ((string= method "SHA384") 48)
                  ((string= method "SHA256") 32)
                  ((string= method "SHA224") 28)
                  ((string= method "SHA1") 20)
                  ((string= method "RIPEMD160") 20)
                  ((string= method "MD5") 16)
                  (t
                   (error "Unknown MD method ~a" method)))))
    (with-foreign-object (output :char length)
      (mbedtls-md-setup *md-ctx* info 0)
      (let ((result
             (mbedtls_md info message (length message) output)))
        (case result
          (0
           (let ((hash
                   (case result-type
                     (:bytes
                      (convert-uint8-array-to-lisp output length))
                     (:chars
                      (convert-uint8-array-to-lisp-string output length)))))
             (mbedtls-md-clear-context *md-ctx*)
             hash))
          (otherwise
           (error (mbedtls-error-text result))))))))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
       
