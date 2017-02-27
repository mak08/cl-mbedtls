;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2017-02-23 23:40:37>

(in-package mbedtls)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;M
;; \brief Translate a mbed TLS error code into a string representation,
;;        Result is truncated if necessary and always includes a terminating
;;        null byte.
;;
;; \param errnum    error code
;; \param buffer    buffer to place representation in
;; \param buflen    length of the buffer
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void mbedtls_strerror( int errnum, char *buffer, size_t buflen );

(defcfun mbedtls_strerror :void (errnum :int) (buffer :string) (len size_t))

(defun mbedtls-strerror (errnum)
  (with-foreign-object (buf :char 1024)
    (mbedtls_strerror errnum buf 1024)
    (cerror "Continue" (foreign-string-to-lisp buf))))

(defun mbedtls-error-text (errnum)
  (let ((text (with-foreign-object (buf :char 1024)
                (mbedtls_strerror errnum buf 1024)
                (foreign-string-to-lisp buf))))
    (log2:trace "mbedTLS error ~a (~a)" text errnum)
    text))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
