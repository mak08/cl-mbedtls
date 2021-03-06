;;; -*- lisp -*- ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert
;;; Created        22/03/2000 11:15:16
;;; Last Modified  <michael 2021-06-19 23:51:42>

(defsystem "cl-mbedtls"
  :description "mbedTLS bindings"
  :default-component-class cl-source-file.cl
  :depends-on ("bordeaux-threads" "cl-utilities" "log2" "makros")
  :serial t
  :components ((:file "package")
               ;; Define & load lxternal library 
               (:file "libraries")
               ;; Generated code  & helpers
               (:file "mbed-ctypes")
               (:file "mbed-aux")
               ;; Bindings by mbedtls header files
               (:file "mbed-error")
               (:file "mbed-debug")
               (:file "mbed-net")
               (:file "mbed-hashing")
               (:file "mbed-crypto")
               (:file "mbed-x509_crt")
               (:file "mbed-entropy")
               (:file "mbed-ctr_drbg")
               (:file "mbed-pk")
               (:file "mbed-ssl")
               (:file "mbed-ssl_cache")
               
               (:file "ciphersuites")
               ;; Lisp programming API
               (:file "api")
               (:file "module-initialization")))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
