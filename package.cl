;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2017-02-23 23:54:49>

(defpackage "MBEDTLS"
  (:use "COMMON-LISP"
        "CFFI"
        #+sbcl "SB-MOP"
        #+clisp "CLOS" ) 
  (:export

   ;; Conditions
   "STREAM-EMPTY-READ"
   "STREAM-READ-ERROR"
   "STREAM-WRITE-ERROR"

   ;; Configuration parameters
   "*KEEPALIVE-TIMEOUT*"
   "*ACCEPT-TIMEOUT*"

   ;; Client
   "CONNECT"

   ;; Server
   "WITH-SERVER-CONNECTION"
   "WITH-SERVER-CONNECTION-ASYNC"
   
   "CREATE-PLAIN-SOCKET-SERVER"
   "CREATE-SSL-SOCKET-SERVER"
   "SOCKET-SERVER"
   "ACCEPT"
   "SERVER-SOCKET"
   "SERVER-PORT"

   ;; Connection/Stream
   "SOCKET-STREAM"
   "PLAIN-STREAM"
   "SSL-STREAM"
   "PEER"
   "FORMAT-IP"
   "KEEPALIVE"
   "GET-LINE"
   "GET-OCTETS"
   "WRITE-TO-STREAM"
   "CLOSE-SOCKET"))

;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
