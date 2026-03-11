;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; util.lisp - Standalone cryptographic utilities for cl-mpc
;;;; No external dependencies - uses SBCL built-ins only

(in-package #:cl-mpc)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defconstant +secp256k1-order+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "Order of the secp256k1 curve, used as default prime for MPC operations.")

(defconstant +wire-label-bytes+ 16
  "Size of wire labels in bytes (128 bits).")

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically random bytes."
  (let ((bytes (make-array n :element-type '(unsigned-byte 8))))
    #+(and sbcl (or linux darwin))
    (with-open-file (urandom "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence bytes urandom))
    #+(and sbcl windows)
    (progn
      ;; On Windows, use SBCL's random with high-quality seed
      (let ((state (sb-ext:seed-random-state t)))
        (dotimes (i n)
          (setf (aref bytes i) (random 256 state)))))
    #-(or (and sbcl linux) (and sbcl darwin) (and sbcl windows))
    (dotimes (i n)
      (setf (aref bytes i) (random 256)))
    bytes))

(defun random-integer (bits)
  "Generate a random integer with BITS bits."
  (bytes-to-integer (get-random-bytes (ceiling bits 8))))

(defun random-below (n)
  "Generate a random integer in [0, n)."
  (mod (random-integer (integer-length n)) n))

;;; ============================================================================
;;; Byte/Integer Conversions
;;; ============================================================================

(defun integer-to-bytes (n &optional (length nil))
  "Convert integer N to a byte array. If LENGTH is provided, pad/truncate to that size."
  (let* ((byte-length (if length
                          length
                          (max 1 (ceiling (integer-length n) 8))))
         (bytes (make-array byte-length :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from (1- byte-length) downto 0
          for shift from 0 by 8
          do (setf (aref bytes i) (ldb (byte 8 shift) n)))
    bytes))

(defun bytes-to-integer (bytes)
  "Convert a byte array to an integer (big-endian)."
  (let ((result 0))
    (loop for b across bytes
          do (setf result (logior (ash result 8) b)))
    result))

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mpc-mod (x p)
  "Compute x mod p, ensuring non-negative result."
  (mod x p))

(defun mpc-mod-add (a b p)
  "Modular addition: (a + b) mod p."
  (mod (+ a b) p))

(defun mpc-mod-sub (a b p)
  "Modular subtraction: (a - b) mod p."
  (mod (- a b) p))

(defun mpc-mod-mul (a b p)
  "Modular multiplication: (a * b) mod p."
  (mod (* a b) p))

(defun mpc-mod-expt (base exp p)
  "Modular exponentiation: base^exp mod p using square-and-multiply."
  (cond
    ((zerop exp) 1)
    ((= exp 1) (mod base p))
    (t (let ((result 1)
             (b (mod base p))
             (e exp))
         (loop while (plusp e)
               do (when (oddp e)
                    (setf result (mod (* result b) p)))
                  (setf e (ash e -1))
                  (setf b (mod (* b b) p)))
         result))))

(defun mpc-mod-inverse (a p)
  "Compute modular multiplicative inverse of a mod p using extended Euclidean algorithm."
  (let ((a (mod a p)))
    (when (zerop a)
      (error "Cannot compute inverse of zero"))
    ;; Extended Euclidean algorithm
    (let ((old-r p) (r a)
          (old-s 0) (s 1))
      (loop while (not (zerop r))
            do (let ((q (floor old-r r)))
                 (psetf old-r r
                        r (- old-r (* q r)))
                 (psetf old-s s
                        s (- old-s (* q s)))))
      (when (/= old-r 1)
        (error "No modular inverse exists for ~A mod ~A" a p))
      (mod old-s p))))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defvar +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defun sha256-rotr (x n)
  "Right rotation of 32-bit value."
  (logand #xFFFFFFFF
          (logior (ash x (- n))
                  (ash x (- 32 n)))))

(defun sha256-ch (x y z)
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-sigma1 (x)
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-gamma0 (x)
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-gamma1 (x)
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (let* ((len (length message))
         (bit-len (* len 8))
         ;; Pad to 448 bits mod 512 (56 bytes mod 64)
         (pad-len (- 64 (mod (+ len 1 8) 64)))
         (pad-len (if (minusp pad-len) (+ pad-len 64) pad-len))
         (total-len (+ len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy message
    (replace padded message)
    ;; Append 0x80
    (setf (aref padded len) #x80)
    ;; Append length as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (ldb (byte 8 (* i 8)) bit-len)))
    padded))

(defun sha256-process-block (block h)
  "Process a 64-byte block and update hash state H."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          do (setf (aref w i)
                   (logior (ash (aref block (* i 4)) 24)
                           (ash (aref block (+ (* i 4) 1)) 16)
                           (ash (aref block (+ (* i 4) 2)) 8)
                           (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xFFFFFFFF
                           (+ (sha256-gamma1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-gamma0 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Initialize working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      ;; Main loop
      (loop for i from 0 below 64
            do (let* ((t1 (logand #xFFFFFFFF
                                  (+ hh
                                     (sha256-sigma1 e)
                                     (sha256-ch e f g)
                                     (aref +sha256-k+ i)
                                     (aref w i))))
                      (t2 (logand #xFFFFFFFF
                                  (+ (sha256-sigma0 a)
                                     (sha256-maj a b c)))))
                 (setf hh g
                       g f
                       f e
                       e (logand #xFFFFFFFF (+ d t1))
                       d c
                       c b
                       b a
                       a (logand #xFFFFFFFF (+ t1 t2)))))
      ;; Update hash values
      (setf (aref h 0) (logand #xFFFFFFFF (+ (aref h 0) a))
            (aref h 1) (logand #xFFFFFFFF (+ (aref h 1) b))
            (aref h 2) (logand #xFFFFFFFF (+ (aref h 2) c))
            (aref h 3) (logand #xFFFFFFFF (+ (aref h 3) d))
            (aref h 4) (logand #xFFFFFFFF (+ (aref h 4) e))
            (aref h 5) (logand #xFFFFFFFF (+ (aref h 5) f))
            (aref h 6) (logand #xFFFFFFFF (+ (aref h 6) g))
            (aref h 7) (logand #xFFFFFFFF (+ (aref h 7) hh))))))

(defun sha256 (data)
  "Compute SHA-256 hash of DATA (byte array). Returns 32-byte array."
  (let ((h (make-array 8 :element-type '(unsigned-byte 32)
                        :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                            #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
        (padded (sha256-pad-message data)))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded i (+ i 64)) h))
    ;; Convert to byte array
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            do (setf (aref result (* i 4)) (ldb (byte 8 24) (aref h i))
                     (aref result (+ (* i 4) 1)) (ldb (byte 8 16) (aref h i))
                     (aref result (+ (* i 4) 2)) (ldb (byte 8 8) (aref h i))
                     (aref result (+ (* i 4) 3)) (ldb (byte 8 0) (aref h i))))
      result)))

;;; ============================================================================
;;; AES-128 for Garbled Circuits (simplified)
;;; ============================================================================

;; AES S-box
(defvar +aes-sbox+
  #(#x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76
    #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0
    #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15
    #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75
    #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84
    #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf
    #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8
    #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2
    #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73
    #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb
    #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79
    #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08
    #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a
    #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e
    #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf
    #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16))

(defun aes-sub-bytes (state)
  (dotimes (i 16)
    (setf (aref state i) (aref +aes-sbox+ (aref state i)))))

(defun aes-shift-rows (state)
  (let ((temp (copy-seq state)))
    ;; Row 1: shift left 1
    (setf (aref state 1) (aref temp 5)
          (aref state 5) (aref temp 9)
          (aref state 9) (aref temp 13)
          (aref state 13) (aref temp 1))
    ;; Row 2: shift left 2
    (setf (aref state 2) (aref temp 10)
          (aref state 6) (aref temp 14)
          (aref state 10) (aref temp 2)
          (aref state 14) (aref temp 6))
    ;; Row 3: shift left 3
    (setf (aref state 3) (aref temp 15)
          (aref state 7) (aref temp 3)
          (aref state 11) (aref temp 7)
          (aref state 15) (aref temp 11))))

(defun aes-xtime (x)
  "Multiply by x in GF(2^8)."
  (let ((result (ash x 1)))
    (if (>= result #x100)
        (logxor result #x11b)
        result)))

(defun aes-mix-column (state col)
  (let* ((c (* col 4))
         (a0 (aref state c))
         (a1 (aref state (+ c 1)))
         (a2 (aref state (+ c 2)))
         (a3 (aref state (+ c 3))))
    (setf (aref state c)
          (logxor (aes-xtime a0) (logxor (aes-xtime a1) a1) a2 a3))
    (setf (aref state (+ c 1))
          (logxor a0 (aes-xtime a1) (logxor (aes-xtime a2) a2) a3))
    (setf (aref state (+ c 2))
          (logxor a0 a1 (aes-xtime a2) (logxor (aes-xtime a3) a3)))
    (setf (aref state (+ c 3))
          (logxor (logxor (aes-xtime a0) a0) a1 a2 (aes-xtime a3)))))

(defun aes-mix-columns (state)
  (dotimes (i 4)
    (aes-mix-column state i)))

(defun aes-add-round-key (state round-key round)
  (let ((offset (* round 16)))
    (dotimes (i 16)
      (setf (aref state i)
            (logxor (aref state i)
                    (aref round-key (+ offset i)))))))

(defvar +aes-rcon+
  #(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1b #x36))

(defun aes-key-expansion (key)
  "Expand 16-byte key to 176-byte round keys."
  (let ((expanded (make-array 176 :element-type '(unsigned-byte 8))))
    ;; Copy original key
    (replace expanded key)
    ;; Generate remaining round keys
    (loop for i from 4 below 44
          for j from 16 by 4
          do (let ((temp (make-array 4 :element-type '(unsigned-byte 8))))
               (replace temp expanded :start2 (- j 4))
               (when (zerop (mod i 4))
                 ;; RotWord
                 (let ((t0 (aref temp 0)))
                   (setf (aref temp 0) (aref temp 1)
                         (aref temp 1) (aref temp 2)
                         (aref temp 2) (aref temp 3)
                         (aref temp 3) t0))
                 ;; SubWord
                 (dotimes (k 4)
                   (setf (aref temp k) (aref +aes-sbox+ (aref temp k))))
                 ;; XOR with Rcon
                 (setf (aref temp 0)
                       (logxor (aref temp 0)
                               (aref +aes-rcon+ (1- (floor i 4))))))
               ;; XOR with word 4 positions back
               (dotimes (k 4)
                 (setf (aref expanded (+ j k))
                       (logxor (aref expanded (+ j k -16))
                               (aref temp k))))))
    expanded))

(defun aes-encrypt-block (plaintext key)
  "AES-128 encrypt a 16-byte block."
  (let ((state (copy-seq plaintext))
        (round-keys (aes-key-expansion key)))
    (aes-add-round-key state round-keys 0)
    (loop for round from 1 below 10
          do (aes-sub-bytes state)
             (aes-shift-rows state)
             (aes-mix-columns state)
             (aes-add-round-key state round-keys round))
    ;; Final round (no MixColumns)
    (aes-sub-bytes state)
    (aes-shift-rows state)
    (aes-add-round-key state round-keys 10)
    state))

;;; ============================================================================
;;; XOR Utilities
;;; ============================================================================

(defun xor-bytes (a b)
  "XOR two byte arrays of equal length."
  (let ((result (make-array (length a) :element-type '(unsigned-byte 8))))
    (dotimes (i (length a))
      (setf (aref result i) (logxor (aref a i) (aref b i))))
    result))

(defun bytes-equal-p (a b)
  "Compare two byte arrays for equality."
  (and (= (length a) (length b))
       (loop for i from 0 below (length a)
             always (= (aref a i) (aref b i)))))

;;; ============================================================================
;;; Hash-based Key Derivation
;;; ============================================================================

(defun hash-to-key (data tweak)
  "Derive a key from data and tweak using SHA-256."
  (let* ((combined (make-array (+ (length data) 4) :element-type '(unsigned-byte 8)))
         (hash nil))
    (replace combined data)
    (setf (aref combined (length data)) (ldb (byte 8 24) tweak)
          (aref combined (+ (length data) 1)) (ldb (byte 8 16) tweak)
          (aref combined (+ (length data) 2)) (ldb (byte 8 8) tweak)
          (aref combined (+ (length data) 3)) (ldb (byte 8 0) tweak))
    (setf hash (sha256 combined))
    (subseq hash 0 16))) ; Return first 16 bytes for AES key

;;; ============================================================================
;;; Lagrange Interpolation
;;; ============================================================================

(defun lagrange-coefficient (i points prime)
  "Compute the Lagrange coefficient for index I given POINTS."
  (let ((xi (car (nth i points)))
        (coeff 1))
    (loop for j from 0 below (length points)
          unless (= i j)
          do (let* ((xj (car (nth j points)))
                    (num (mpc-mod-sub 0 xj prime))
                    (den (mpc-mod-sub xi xj prime)))
               (setf coeff (mpc-mod-mul coeff
                                        (mpc-mod-mul num (mpc-mod-inverse den prime) prime)
                                        prime))))
    coeff))

(defun lagrange-interpolate (points prime)
  "Interpolate the secret (f(0)) from POINTS using Lagrange interpolation."
  (let ((secret 0))
    (loop for i from 0 below (length points)
          do (let* ((yi (cdr (nth i points)))
                    (li (lagrange-coefficient i points prime)))
               (setf secret (mpc-mod-add secret
                                         (mpc-mod-mul yi li prime)
                                         prime))))
    secret))
