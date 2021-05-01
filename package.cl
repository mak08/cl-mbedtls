;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2021-04-30 21:10:37>

(defpackage "MBEDTLS"
  (:use "COMMON-LISP"
        "CFFI"
        #+sbcl "SB-MOP"
        #+clisp "CLOS" ) 
  (:export

   ;; Conditions
   "STREAM-TIMEOUT"
   "STREAM-EMPTY-READ"
   "STREAM-READ-ERROR"
   "STREAM-WRITE-ERROR"

   ;; Configuration parameters
   "*KEEPALIVE-TIMEOUT*"
   "*ACCEPT-TIMEOUT*"

   ;; Client
   "CONNECT"

   ;; Server
   "WITH-SERVER"

   "CREATE-PLAIN-SOCKET-SERVER"
   "CREATE-SSL-SOCKET-SERVER"
   "DEALLOCATE"

   "SERVER-SOCKET"
   "SERVER-PORT"

   ;; Connections
   "WITH-SERVER-CONNECTION"
   "WITH-SERVER-CONNECTION-ASYNC"
   
   "SOCKET-SERVER"
   "ACCEPT"
   "CLOSE-SOCKET"

   "KEEPALIVE"
   
   ;; Streams
   "SOCKET-STREAM"
   "PLAIN-STREAM"
   "SSL-STREAM"
   "PEER"
   "FORMAT-IP"
   "GET-LINE"
   "GET-OCTETS"
   "WRITE-TO-STREAM"

   ;; Hashing
   "MBEDTLS-MD-LIST-NAMES"
   "MBEDTLS-MD"
   ))

;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

