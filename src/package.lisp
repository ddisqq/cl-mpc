;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; package.lisp - Package definition for cl-mpc
;;;; Standalone Multi-Party Computation library

(defpackage #:cl-mpc
  (:use #:cl)
  (:documentation "Pure Common Lisp Multi-Party Computation library.
Implements Shamir Secret Sharing, Verifiable Secret Sharing (Feldman/Pedersen),
Distributed Key Generation, Oblivious Transfer, Garbled Circuits, and SPDZ protocol.")

  ;; Constants
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:+secp256k1-order+
           #:+wire-label-bytes+)

  ;; Utility functions
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:get-random-bytes
           #:random-integer
           #:random-below
           #:integer-to-bytes
           #:bytes-to-integer
           #:xor-bytes
           #:bytes-equal-p
           #:sha256
           #:aes-encrypt-block
           #:hash-to-key)

  ;; Modular arithmetic
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:mpc-mod
           #:mpc-mod-add
           #:mpc-mod-sub
           #:mpc-mod-mul
           #:mpc-mod-expt
           #:mpc-mod-inverse
           #:lagrange-coefficient
           #:lagrange-interpolate)

  ;; Secret Sharing types
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:secret-share
           #:secret-share-index
           #:secret-share-value
           #:secret-share-threshold
           #:secret-share-prime
           #:make-secret-share
           #:secret-share-p

           #:share-commitment
           #:share-commitment-index
           #:share-commitment-commitment
           #:share-commitment-proof
           #:make-share-commitment
           #:share-commitment-p)

  ;; Shamir Secret Sharing
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:split-secret
           #:reconstruct-secret
           #:verify-share
           #:refresh-shares
           #:add-shares
           #:sub-shares
           #:scalar-mul-share)

  ;; Verifiable Secret Sharing
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:vss-commitment
           #:vss-commitment-coefficients
           #:vss-commitment-generator
           #:make-vss-commitment
           #:vss-commitment-p

           #:vss-share
           #:vss-share-index
           #:vss-share-value
           #:vss-share-commitment
           #:make-vss-share
           #:vss-share-p

           #:feldman-vss-split
           #:feldman-vss-verify
           #:pedersen-vss-split
           #:pedersen-vss-verify)

  ;; Distributed Key Generation
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:dkg-party-state
           #:dkg-party-state-id
           #:dkg-party-state-threshold
           #:dkg-party-state-num-parties
           #:make-dkg-party-state
           #:dkg-party-state-p

           #:dkg-result
           #:dkg-result-public-key
           #:dkg-result-share
           #:dkg-result-verification-vector
           #:make-dkg-result
           #:dkg-result-p

           #:dkg-init-party
           #:dkg-generate-shares
           #:dkg-receive-share
           #:dkg-complete)

  ;; Proactive Secret Sharing
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:proactive-refresh
           #:proactive-update-share)

  ;; MPC Arithmetic
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:mpc-add-shares
           #:mpc-sub-shares
           #:mpc-scalar-mul-share)

  ;; Beaver Triples
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:beaver-triple
           #:beaver-triple-a
           #:beaver-triple-b
           #:beaver-triple-c
           #:make-beaver-triple
           #:beaver-triple-p
           #:generate-beaver-triple
           #:mpc-multiply-shares-beaver)

  ;; Packed Secret Sharing
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:packed-split-secrets
           #:packed-reconstruct-secrets)

  ;; Oblivious Transfer types
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:ot-sender-state
           #:ot-sender-state-private-key
           #:ot-sender-state-public-key
           #:make-ot-sender-state
           #:ot-sender-state-p

           #:ot-receiver-state
           #:ot-receiver-state-choice
           #:ot-receiver-state-private-key
           #:make-ot-receiver-state
           #:ot-receiver-state-p

           #:ot-message
           #:ot-message-ciphertext0
           #:ot-message-ciphertext1
           #:make-ot-message
           #:ot-message-p)

  ;; 1-of-2 Oblivious Transfer
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:ot-sender-init
           #:ot-receiver-choose
           #:ot-sender-transfer
           #:ot-receiver-decrypt)

  ;; 1-of-n Oblivious Transfer
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:ot-n-sender-init
           #:ot-n-receiver-choose
           #:ot-n-sender-transfer
           #:ot-n-receiver-decrypt)

  ;; Base OT (Chou-Orlandi)
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:base-ot-sender-setup
           #:base-ot-receiver-choose
           #:base-ot-sender-encrypt
           #:base-ot-receiver-decrypt)

  ;; OT Extension (IKNP)
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:ot-extension-state
           #:ot-extension-init
           #:ot-extension-receiver-setup
           #:ot-extension-sender-respond
           #:ot-extension-transfer)

  ;; Random OT
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:random-ot-sender-init
           #:random-ot-receiver-choose
           #:random-ot-complete)

  ;; Correlated OT
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:correlated-ot-sender-init
           #:correlated-ot-receiver-choose
           #:correlated-ot-complete)

  ;; Batched OT
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:batched-ot-sender-init
           #:batched-ot-receiver-choose
           #:batched-ot-transfer)

  ;; Garbled Circuit types
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:wire-label
           #:wire-label-value
           #:wire-label-pointer-bit
           #:make-wire-label
           #:wire-label-p

           #:garbled-wire
           #:garbled-wire-id
           #:garbled-wire-label0
           #:garbled-wire-label1
           #:make-garbled-wire
           #:garbled-wire-p

           #:garbled-gate
           #:garbled-gate-id
           #:garbled-gate-type
           #:garbled-gate-input-wires
           #:garbled-gate-output-wire
           #:garbled-gate-table
           #:make-garbled-gate
           #:garbled-gate-p

           #:garbled-circuit
           #:garbled-circuit-gates
           #:garbled-circuit-input-wires
           #:garbled-circuit-output-wires
           #:garbled-circuit-global-offset
           #:make-garbled-circuit
           #:garbled-circuit-p)

  ;; Garbled Circuit operations
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:generate-wire-labels
           #:garble-and-gate
           #:garble-xor-gate
           #:garble-and-gate-half-gates
           #:garble-gate-row-reduction
           #:garble-circuit
           #:evaluate-garbled-circuit
           #:encode-input
           #:decode-output)

  ;; 2PC Protocol
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:gc-2pc-garble
           #:gc-2pc-evaluate
           #:gc-2pc-run)

  ;; Example circuits
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:make-and-circuit
           #:make-or-circuit
           #:make-xor-circuit
           #:make-not-circuit
           #:make-equality-circuit
           #:make-millionaires-circuit
           #:make-adder-circuit
           #:make-comparator-circuit)

  ;; SPDZ types
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:spdz-share
           #:spdz-share-value
           #:spdz-share-mac
           #:make-spdz-share
           #:spdz-share-p

           #:spdz-party
           #:spdz-party-id
           #:spdz-party-mac-key-share
           #:spdz-party-shares
           #:make-spdz-party
           #:spdz-party-p)

  ;; SPDZ operations
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:generate-mac-key-shares
           #:spdz-share-secret
           #:spdz-add
           #:spdz-subtract
           #:spdz-multiply-by-constant
           #:spdz-multiply
           #:spdz-multiply-finish
           #:spdz-open
           #:spdz-open-with-check
           #:spdz-mac-check)

  ;; SPDZ protocol execution
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:run-spdz-addition
           #:run-spdz-multiplication
           #:run-spdz-circuit)

  ;; High-level interface
  (:export
   #:with-mpc-timing
   #:mpc-batch-process
   #:mpc-health-check#:mpc-session
           #:mpc-session-parties
           #:mpc-session-threshold
           #:make-mpc-session
           #:mpc-session-p

           #:mpc-share-secret
           #:mpc-reconstruct
           #:mpc-compute
           #:mpc-verify-result))
