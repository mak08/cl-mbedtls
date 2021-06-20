;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Description
;;; Author         Michael Kappert 2021
;;; Last Modified <michael 2021-06-19 23:48:24>

(in-package mbedtls)

(eval-when (:load-toplevel :compile-toplevel :execute)
  (defun initialize-module ()
    (log2:info "Initializing md context")
    (setf *md-ctx*
          (mbedtls-md-init))))

(eval-when (:load-toplevel :execute)
  (push #'initialize-module sb-ext:*init-hooks*)
  (initialize-module))

;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
