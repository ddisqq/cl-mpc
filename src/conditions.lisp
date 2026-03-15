;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-mpc)

(define-condition cl-mpc-error (error)
  ((message :initarg :message :reader cl-mpc-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-mpc error: ~A" (cl-mpc-error-message condition)))))
