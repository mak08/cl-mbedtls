;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description   CAUTION !!  By contrast to datatypes.c/datatypes.cl,
;;;               THIS FILE IS NOT generated from ssl_aux.c
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2019-02-03 19:12:43>

(in-package mbedtls)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(pushnew (asdf:system-source-directory :cl-mbedtls)
         *foreign-library-directories*
         :test #'equalp)

(define-foreign-library libmbed-aux
  (:linux "libmbed_aux.so"))
(define-foreign-library libmbedtls
  (:linux "libmbedtls.so"))
(define-foreign-library libmbedcrypto
  (:linux "libmbedcrypto.so"))
(define-foreign-library libmbedx509
  (:linux "libmbedx509.so"))

;;; Load order is important! (see mbedtls-2.16.0/README.md)
(use-foreign-library libmbedcrypto)
(use-foreign-library libmbedx509)
(use-foreign-library libmbedtls)
;;; This is our own and depends on all of the previous.
(use-foreign-library libmbed-aux)

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
