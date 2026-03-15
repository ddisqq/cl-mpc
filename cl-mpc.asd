;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-mpc.asd - System definition for cl-mpc
;;;; Pure Common Lisp Multi-Party Computation Library
;;;; Copyright (c) 2024-2026 Parkian Company LLC
;;;; License: BSD-3-Clause

(asdf:defsystem #:cl-mpc
  :description "Pure Common Lisp Multi-Party Computation library with zero external dependencies.
Implements Shamir Secret Sharing, Verifiable Secret Sharing (Feldman/Pedersen),
Distributed Key Generation, Oblivious Transfer, Garbled Circuits, and SPDZ protocol."
  :author "Park Ian Co"
  :license "Apache-2.0"
  :version "0.1.0"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "package")
                             (:file "conditions" :depends-on ("package"))
                             (:file "types" :depends-on ("package"))
                             (:file "cl-mpc" :depends-on ("package" "conditions" "types"))))))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-mpc/test))))

(asdf:defsystem #:cl-mpc/test
  :description "Tests for cl-mpc"
  :depends-on (#:cl-mpc)
  :serial t
  :components ((:module "test"
                :components ((:file "test-suite"))))
  :perform (asdf:test-op (op c)
             (let ((result (uiop:symbol-call :cl-mpc/test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))
