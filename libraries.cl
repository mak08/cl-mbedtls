;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description   CAUTION !!  By contrast to datatypes.c/datatypes.cl,
;;;               THIS FILE IS NOT generated from ssl_aux.c
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2021-06-08 21:36:24>

(in-package mbedtls)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(pushnew (asdf:system-source-directory :cl-mbedtls)
         *foreign-library-directories*
         :test #'equalp)

(define-foreign-library libmbed-aux
  (:linux "libmbed_aux.so"))
(define-foreign-library libmbedtls
  (:linux #.(macros:get-library "libmbedtls.so.12")))
(define-foreign-library libmbedcrypto
  (:linux #.(macros:get-library "libmbedcrypto.so.3")))
(define-foreign-library libmbedx509
  (:linux #.(macros:get-library "libmbedx509.so.0")))

;;; Load order is important! (see mbedtls-2.16.0/README.md)
(use-foreign-library libmbedcrypto)
(use-foreign-library libmbedx509)
(use-foreign-library libmbedtls)
;;; This is our own and depends on all of the previous.
(use-foreign-library libmbed-aux)

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
