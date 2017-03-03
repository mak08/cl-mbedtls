;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description   CAUTION !!  By contrast to datatypes.c/datatypes.cl,
;;;               THIS FILE IS NOT generated from ssl_aux.c
;;; Author         Michael Kappert 2015
;;; Last Modified <michael 2017-02-15 23:04:27>

(in-package mbedtls)
(declaim (optimize (debug 0) (safety 0) (speed 3) (space 0)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Some useful C functions 

(defcvar "stdout" :pointer)
(defcvar "stderr" :pointer)
(defcvar "errno" :int)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; User functions

(defcvar "my_debug_function" :pointer)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Sockets

(defcfun "getsockopt" :int
  (sockfd :int)
  (level :int)
  (optname :int)
  (optval :pointer)
  (optlen :int))
  
(defcfun "setsockopt" :int
  (sockfd :int)
  (level :int)
  (optname :int)
  (optval :pointer)
  (optlen :int))

(defcfun "poll" :int
  (fds (:pointer (:struct pollfd)))
  (n_fds :int)
  (timeout :int))

(defcfun "inet_ntop" :string
  (af :int)
  (src :pointer)
  (dst :pointer)
  (size :int))
  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Callbacks - remember the earmuffs

;;; net.h / BIO 
(defcvar "net_send_function" :pointer)
(defcvar "net_recv_function" :pointer)
(defcvar "net_recv_timeout_function" :pointer)

;;; entropy.h
(defcvar "mbedtls_entropy_func_function" :pointer)

;;; ctr_drbg.h
(defcvar "mbedtls_ctr_drbg_random_function" :pointer)

;;; ssl_cache.h
(defcvar "mbedtls_ssl_cache_get_function" :pointer)
(defcvar "mbedtls_ssl_cache_set_function" :pointer)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helper functions

(defcfun "memset" :void (buf :pointer) (c :uchar) (len size_t))

(defun clear-buffer (buf len)
  (memset buf 0 len))

(defun foreign-type-to-lisp (type)
  (ecase type
    (:int8  '(unsigned-byte 8))
    (:uint8 '(unsigned-byte 8))
    (:int16 '(unsigned-byte 16))
    (:int32 '(unsigned-byte 32))))

(defmacro with-foreign-array ((array-var array c-element-type) &body body)
  `(let ((,array-var (convert-array-to-foreign ,array ,c-element-type)))
     (unwind-protect
          (progn ,@body)
       (foreign-free ,array-var))))

(defun convert-array-to-foreign (array c-element-type)
  (let ((res (foreign-alloc c-element-type :count (length array))))
    (dotimes (i (length array) res)
      (setf (mem-aref res c-element-type i) (aref array i)))))

(defun convert-array-to-lisp (foreign-array element-type length
                              &aux (result (make-array length
                                                       :element-type (foreign-type-to-lisp element-type))))
  (unless (null-pointer-p foreign-array)
    (loop
       :for k :below length
       :do (setf (aref result k)
                 (mem-aref foreign-array element-type k)))
    (values result)))
(defun convert-uint8-array-to-lisp (foreign-array length
                                    &aux (result (make-array length
                                                             :element-type (foreign-type-to-lisp :uint8))))
  (unless (null-pointer-p foreign-array)
    (loop
       :for k :below length
       :do (setf (aref result k)
                 (mem-aref foreign-array :uint8 k)))
    (values result)))


(defun convert-array-nil-to-lisp (foreign-array element-type
                                  &aux (result (make-array  0
                                                            :adjustable t :fill-pointer 0
                                                            :element-type (foreign-type-to-lisp element-type))))  
  (unless (null-pointer-p foreign-array)
    (loop
       :for k :from 0
       :for element = (mem-aref foreign-array element-type k)
       :while element
       :do (vector-push-extend element result))
    (values result)))

;;; EOF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;