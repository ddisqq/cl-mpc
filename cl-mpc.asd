;;;; cl-mpc.asd - System definition for cl-mpc
;;;; Pure Common Lisp Multi-Party Computation Library
;;;; Copyright (c) 2024-2026 Parkian Company LLC
;;;; License: BSD-3-Clause

(asdf:defsystem #:cl-mpc
  :description "Pure Common Lisp Multi-Party Computation library with zero external dependencies.
Implements Shamir Secret Sharing, Verifiable Secret Sharing (Feldman/Pedersen),
Distributed Key Generation, Oblivious Transfer, Garbled Circuits, and SPDZ protocol."
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "0.1.0"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "sharing")
                             (:file "garbled")
                             (:file "protocol"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-mpc/test))))

(asdf:defsystem #:cl-mpc/test
  :description "Tests for cl-mpc"
  :depends-on (#:cl-mpc)
  :serial t
  :components ((:module "test"
                :components ((:file "test-suite"))))
  :perform (asdf:test-op (op c)
             (uiop:symbol-call :cl-mpc/test :run-all-tests)))
