;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description   CAUTION !!  By contrast to datatypes.c/datatypes.cl,
;;;               THIS FILE IS NOT generated from ssl_aux.c
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2017-02-28 22:56:47>

(in-package mbedtls)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(pushnew (asdf:system-source-directory :cl-mbedtls)
         *foreign-library-directories*
         :test #'equalp)

(define-foreign-library libmbed-aux
  (:linux "./libmbed_aux.so"))
(define-foreign-library libmbedtls
  (:linux "/usr/local/lib/libmbedtls.so"))
(define-foreign-library libmbedcrypto
  (:linux "/usr/local/lib/libmbedcrypto.so"))
(define-foreign-library libmbedx509
  (:linux "/usr/local/lib/libmbedx509.so"))

(use-foreign-library libmbedx509)
(use-foreign-library libmbedcrypto)
(use-foreign-library libmbedtls)
(use-foreign-library libmbed-aux)

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
