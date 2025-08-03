;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2025-07-27 21:26:21>

(in-package mbedtls)

(defparameter +mozilla-ciphers+
  '("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
    "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"
    "TLS-ECDHE-RSA-WITH-AES-128-SHA256"
    "TLS-ECDHE-ECDSA-WITH-AES-128-SHA256"
    "TLS-ECDHE-RSA-WITH-AES-128-SHA"
    "TLS-ECDHE-ECDSA-WITH-AES-128-SHA"
    "TLS-ECDHE-RSA-WITH-AES-256-SHA384"
    "TLS-ECDHE-ECDSA-WITH-AES-256-SHA384"
    "TLS-ECDHE-RSA-WITH-AES-256-SHA"
    "TLS-ECDHE-ECDSA-WITH-AES-256-SHA"
    "TLS-DHE-RSA-WITH-AES-128-SHA256"
    "TLS-DHE-RSA-WITH-AES-128-SHA"
    "TLS-DHE-DSS-WITH-AES-128-SHA256"
    "TLS-DHE-RSA-WITH-AES-256-SHA256"
    "TLS-DHE-DSS-WITH-AES-256-SHA"
    "TLS-DHE-RSA-WITH-AES-256-SHA"))

(defparameter +good-ciphers+
  '("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
    "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"
    "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"
    "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"
    "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"
    "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"
    "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"
    "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"
    "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"
    "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"
    "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"
    "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"
    "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"
    "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"
    "TLS-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-RSA-WITH-AES-256-GCM-SHA384"
    "TLS-RSA-WITH-AES-128-CBC-SHA256"
    "TLS-RSA-WITH-AES-256-CBC-SHA256"
    "TLS-RSA-WITH-AES-128-CBC-SHA"
    "TLS-RSA-WITH-AES-256-CBC-SHA"
    "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"
    "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"
    "TLS-SRP-SHA-WITH-AES-256-CBC-SHA"
    "TLS-DH-DSS-WITH-AES-256-GCM-SHA384"
    "TLS-DH-RSA-WITH-AES-256-GCM-SHA384"
    "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"
    "TLS-DH-RSA-WITH-AES-256-CBC-SHA256"
    "TLS-DH-DSS-WITH-AES-256-CBC-SHA256"
    "TLS-DH-RSA-WITH-AES-256-CBC-SHA"
    "TLS-DH-DSS-WITH-AES-256-CBC-SHA"
    "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"
    "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"
    "TLS-SRP-SHA-WITH-AES-128-CBC-SHA"
    "TLS-DH-DSS-WITH-AES-128-GCM-SHA256"
    "TLS-DH-RSA-WITH-AES-128-GCM-SHA256"
    "TLS-DH-RSA-WITH-AES-128-CBC-SHA256"
    "TLS-DH-DSS-WITH-AES-128-CBC-SHA256"
    "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"
    "TLS-DH-RSA-WITH-AES-128-CBC-SHA"
    "TLS-DH-DSS-WITH-AES-128-CBC-SHA"
    "TLS-RSA-WITH-3DES-EDE-CBC-SHA"
    "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"
    "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"
    "TLS-DH-RSA-WITH-CAMELLIA-256-CBC-SHA"
    "TLS-DH-DSS-WITH-CAMELLIA-256-CBC-SHA"
    "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"
    "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"
    "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"
    "TLS-DH-RSA-WITH-CAMELLIA-128-CBC-SHA"
    "TLS-DH-DSS-WITH-CAMELLIA-128-CBC-SHA"
    "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"))

(defun list-ciphersuites ()
  (let ((l (mbedtls-ssl-list-ciphersuites)))
    (loop
       :for k :from 0
       :for s = (mem-aref l :int k)
       :while (> s 0)
       :collect (cons s (mbedtls-ssl-get-ciphersuite-name s)))))

(defun match-ciphersuite (name &key
                          (ciphers-list +mozilla-ciphers+)
                          (key-exchange nil)
                          (authentication nil)
                          (hash nil)
                          (encryption nil))
  (handler-case 
      (destructuring-bind (prefix ke auth with h encr &rest broken)
          (cl-utilities:split-sequence #\- name )
        (and  (or (null ciphers-list)
                  (member name ciphers-list :test #'string-equal))
              (or (null key-exchange)
                  (string= key-exchange ke))
              (or (null authentication)
                  (string= authentication auth))
              (or (null hash)
                  (string= hash h))
              (or (null encryption)
                  (string= encryption encr))))
    (error (e)
      (log2:warning "Unhandled ciphersuite ~a" name)
      (values nil))))
          
(defun get-ciphers (&key
                    (ciphers-list +mozilla-ciphers+)
                    (key-exchange nil)
                    (authentication nil)
                    (hash nil)
                    (encryption nil))
  (let* ((all-ciphers (mbedtls-ssl-list-ciphersuites))
         (ciphers
          (loop
             :for k :from 0
             :for s = (mem-aref all-ciphers :int k)
             :for sn = (mbedtls-ssl-get-ciphersuite-name s)
             :while (> s 0)
             :when (match-ciphersuite sn
                                      :ciphers-list ciphers-list
                                      :key-exchange key-exchange
                                      :authentication authentication
                                      :hash hash
                                      :encryption encryption)
             :collect s)))
    (make-array (length ciphers) :initial-contents ciphers)))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
