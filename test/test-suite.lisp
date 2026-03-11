;;;; test-suite.lisp - Test suite for cl-mpc
;;;; Copyright (c) 2024-2026 Parkian Company LLC
;;;; License: BSD-3-Clause

(defpackage #:cl-mpc/test
  (:use #:cl #:cl-mpc)
  (:export #:run-all-tests))

(in-package #:cl-mpc/test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)
(defvar *current-test* nil)

(defmacro deftest (name &body body)
  "Define a test."
  `(defun ,name ()
     (setf *current-test* ',name)
     (handler-case
         (progn ,@body)
       (error (e)
         (format t "~&ERROR in ~A: ~A~%" ',name e)
         (incf *fail-count*)))))

(defun check (condition &optional message)
  "Check a condition, record pass/fail."
  (incf *test-count*)
  (if condition
      (incf *pass-count*)
      (progn
        (incf *fail-count*)
        (format t "~&FAIL [~A]: ~A~%" *current-test* (or message "check failed")))))

(defun check-equal (actual expected &optional message)
  "Check equality."
  (let ((msg (if (equal actual expected)
                 message
                 (format nil "~A: Expected ~A, got ~A"
                         (or message "check-equal") expected actual))))
    (check (equal actual expected) msg)))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-random-bytes
  (let ((bytes (get-random-bytes 32)))
    (check (= (length bytes) 32) "Random bytes length")
    (check (typep bytes '(simple-array (unsigned-byte 8) (*))) "Random bytes type")))

(deftest test-integer-bytes-conversion
  (let* ((n 12345678901234567890)
         (bytes (integer-to-bytes n))
         (result (bytes-to-integer bytes)))
    (check-equal result n "Integer roundtrip")))

(deftest test-modular-arithmetic
  (let ((p 997))  ; Small prime for testing
    (check-equal (mpc-mod-add 500 600 p) 103 "Modular add")
    (check-equal (mpc-mod-sub 100 200 p) 897 "Modular sub")
    (check-equal (mpc-mod-mul 50 30 p) 503 "Modular mul")
    (check-equal (mpc-mod-expt 2 10 p) 27 "Modular expt")
    (let ((inv (mpc-mod-inverse 123 p)))
      (check-equal (mpc-mod-mul 123 inv p) 1 "Modular inverse"))))

(deftest test-sha256
  (let* ((input (make-array 3 :element-type '(unsigned-byte 8)
                              :initial-contents '(97 98 99)))  ; "abc"
         (hash (sha256 input)))
    (check (= (length hash) 32) "SHA256 output length")
    ;; Known test vector for "abc"
    (check (= (aref hash 0) #xba) "SHA256 first byte")))

(deftest test-aes-encrypt
  (let* ((key (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (plaintext (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (ciphertext (aes-encrypt-block plaintext key)))
    (check (= (length ciphertext) 16) "AES output length")
    (check (not (equalp plaintext ciphertext)) "AES encrypts")))

(deftest test-xor-bytes
  (let* ((a (make-array 4 :element-type '(unsigned-byte 8)
                          :initial-contents '(#xAA #xBB #xCC #xDD)))
         (b (make-array 4 :element-type '(unsigned-byte 8)
                          :initial-contents '(#x55 #x55 #x55 #x55)))
         (result (xor-bytes a b)))
    (check-equal (aref result 0) #xFF "XOR byte 0")
    (check-equal (aref result 1) #xEE "XOR byte 1")))

;;; ============================================================================
;;; Secret Sharing Tests
;;; ============================================================================

(deftest test-shamir-split-reconstruct
  (let* ((secret 12345)
         (n 5)
         (threshold 3)
         (prime 65537)
         (shares (split-secret secret n threshold :prime prime)))
    (check (= (length shares) n) "Correct number of shares")
    ;; Reconstruct with threshold shares
    (let ((subset (subseq shares 0 threshold)))
      (check-equal (reconstruct-secret subset :prime prime) secret
                   "Reconstruct with threshold"))
    ;; Reconstruct with all shares
    (check-equal (reconstruct-secret shares :prime prime) secret
                 "Reconstruct with all shares")))

(deftest test-shamir-different-subsets
  (let* ((secret 12345)  ; Must be < prime
         (prime 65537)
         (shares (split-secret secret 5 3 :prime prime)))
    ;; Try different 3-share subsets
    (check-equal (reconstruct-secret (list (nth 0 shares) (nth 1 shares) (nth 2 shares))
                                     :prime prime)
                 secret "Subset 0,1,2")
    (check-equal (reconstruct-secret (list (nth 0 shares) (nth 2 shares) (nth 4 shares))
                                     :prime prime)
                 secret "Subset 0,2,4")
    (check-equal (reconstruct-secret (list (nth 1 shares) (nth 3 shares) (nth 4 shares))
                                     :prime prime)
                 secret "Subset 1,3,4")))

(deftest test-share-arithmetic
  (let* ((prime 65537)
         (secret1 100)
         (secret2 200)
         (shares1 (split-secret secret1 3 2 :prime prime))
         (shares2 (split-secret secret2 3 2 :prime prime)))
    ;; Add shares
    (let ((sum-shares (loop for s1 in shares1
                            for s2 in shares2
                            collect (add-shares s1 s2))))
      (check-equal (reconstruct-secret sum-shares :prime prime)
                   (mod (+ secret1 secret2) prime)
                   "Share addition"))
    ;; Scalar multiply
    (let ((scaled (mapcar (lambda (s) (scalar-mul-share s 5)) shares1)))
      (check-equal (reconstruct-secret scaled :prime prime)
                   (mod (* secret1 5) prime)
                   "Scalar multiplication"))))

(deftest test-feldman-vss
  ;; Use default prime (secp256k1-order) for consistency
  (let* ((secret 42))
    (multiple-value-bind (shares commitment)
        (feldman-vss-split secret 5 3)
      (check (= (length shares) 5) "Feldman share count")
      (check (vss-commitment-p commitment) "Valid commitment")
      ;; Verify each share
      (dolist (share shares)
        (check (feldman-vss-verify share commitment)
               "Feldman verification")))))

(deftest test-refresh-shares
  (let* ((secret 777)
         (prime 65537)
         (shares (split-secret secret 4 2 :prime prime))
         (refreshed (refresh-shares shares :prime prime)))
    ;; Values should change
    (check (not (= (secret-share-value (first shares))
                   (secret-share-value (first refreshed))))
           "Refresh changes values")
    ;; But reconstruction should give same secret
    (check-equal (reconstruct-secret refreshed :prime prime) secret
                 "Refresh preserves secret")))

(deftest test-beaver-triple
  (let* ((prime 65537)
         (triples (generate-beaver-triple 3 2 :prime prime)))
    (check (= (length triples) 3) "Triple count")
    ;; Verify c = a*b for the combined values
    (let* ((a (reconstruct-secret (mapcar #'beaver-triple-a triples) :prime prime))
           (b (reconstruct-secret (mapcar #'beaver-triple-b triples) :prime prime))
           (c (reconstruct-secret (mapcar #'beaver-triple-c triples) :prime prime)))
      (check-equal c (mod (* a b) prime) "Beaver triple relation"))))

;;; ============================================================================
;;; Garbled Circuit Tests
;;; ============================================================================

(deftest test-and-circuit
  ;; Use standard garbling (not half-gates) for more reliable testing
  (let* ((circuit-spec (make-and-circuit))
         (gc0 (garble-circuit circuit-spec :optimization :standard))
         (gc1 (garble-circuit circuit-spec :optimization :standard))
         (gc2 (garble-circuit circuit-spec :optimization :standard))
         (gc3 (garble-circuit circuit-spec :optimization :standard)))
    (check-equal (decode-output gc0 (evaluate-garbled-circuit gc0 (encode-input gc0 '(0 0)))) '(0) "0 AND 0")
    (check-equal (decode-output gc1 (evaluate-garbled-circuit gc1 (encode-input gc1 '(0 1)))) '(0) "0 AND 1")
    (check-equal (decode-output gc2 (evaluate-garbled-circuit gc2 (encode-input gc2 '(1 0)))) '(0) "1 AND 0")
    (check-equal (decode-output gc3 (evaluate-garbled-circuit gc3 (encode-input gc3 '(1 1)))) '(1) "1 AND 1")))

(deftest test-or-circuit
  ;; Use standard garbling for OR
  (let* ((circuit-spec (make-or-circuit))
         (gc0 (garble-circuit circuit-spec :optimization :standard))
         (gc1 (garble-circuit circuit-spec :optimization :standard))
         (gc2 (garble-circuit circuit-spec :optimization :standard))
         (gc3 (garble-circuit circuit-spec :optimization :standard)))
    (check-equal (decode-output gc0 (evaluate-garbled-circuit gc0 (encode-input gc0 '(0 0)))) '(0) "0 OR 0")
    (check-equal (decode-output gc1 (evaluate-garbled-circuit gc1 (encode-input gc1 '(0 1)))) '(1) "0 OR 1")
    (check-equal (decode-output gc2 (evaluate-garbled-circuit gc2 (encode-input gc2 '(1 0)))) '(1) "1 OR 0")
    (check-equal (decode-output gc3 (evaluate-garbled-circuit gc3 (encode-input gc3 '(1 1)))) '(1) "1 OR 1")))

(deftest test-xor-circuit
  ;; XOR uses free-xor optimization which is simpler
  (let* ((circuit-spec (make-xor-circuit))
         (gc0 (garble-circuit circuit-spec :optimization :free-xor))
         (gc1 (garble-circuit circuit-spec :optimization :free-xor))
         (gc2 (garble-circuit circuit-spec :optimization :free-xor))
         (gc3 (garble-circuit circuit-spec :optimization :free-xor)))
    (check-equal (decode-output gc0 (evaluate-garbled-circuit gc0 (encode-input gc0 '(0 0)))) '(0) "0 XOR 0")
    (check-equal (decode-output gc1 (evaluate-garbled-circuit gc1 (encode-input gc1 '(0 1)))) '(1) "0 XOR 1")
    (check-equal (decode-output gc2 (evaluate-garbled-circuit gc2 (encode-input gc2 '(1 0)))) '(1) "1 XOR 0")
    (check-equal (decode-output gc3 (evaluate-garbled-circuit gc3 (encode-input gc3 '(1 1)))) '(0) "1 XOR 1")))

(deftest test-garbled-circuit-encode-decode
  (let* ((circuit-spec (make-and-circuit))
         (gc (garble-circuit circuit-spec)))
    ;; Test encoding
    (let ((labels (encode-input gc '(1 0))))
      (check (= (length labels) 2) "Encoded input count")
      (check (wire-label-p (first labels)) "Valid wire label"))))

;;; ============================================================================
;;; Oblivious Transfer Tests
;;; ============================================================================

(deftest test-ot-1-of-2
  (let* ((sender (ot-sender-init))
         (m0 (integer-to-bytes 12345 32))
         (m1 (integer-to-bytes 67890 32)))
    ;; Test choice = 0
    (multiple-value-bind (receiver blinded)
        (ot-receiver-choose (ot-sender-state-public-key sender) 0)
      (let* ((ot-msg (ot-sender-transfer sender blinded m0 m1))
             (result (ot-receiver-decrypt receiver
                                          (ot-sender-state-public-key sender)
                                          ot-msg)))
        (check (bytes-equal-p result m0) "OT choice=0 gets m0")))
    ;; Test choice = 1
    (multiple-value-bind (receiver blinded)
        (ot-receiver-choose (ot-sender-state-public-key sender) 1)
      (let* ((ot-msg (ot-sender-transfer sender blinded m0 m1))
             (result (ot-receiver-decrypt receiver
                                          (ot-sender-state-public-key sender)
                                          ot-msg)))
        (check (bytes-equal-p result m1) "OT choice=1 gets m1")))))

(deftest test-base-ot
  (multiple-value-bind (y S) (base-ot-sender-setup)
    (let ((m0 (integer-to-bytes 111 32))
          (m1 (integer-to-bytes 222 32)))
      ;; Choice = 0
      (multiple-value-bind (x R choice) (base-ot-receiver-choose S 0)
        (multiple-value-bind (c0 c1) (base-ot-sender-encrypt y S R m0 m1)
          (let ((result (base-ot-receiver-decrypt x S choice c0 c1)))
            (check (bytes-equal-p result m0) "Base OT choice=0"))))
      ;; Choice = 1
      (multiple-value-bind (x R choice) (base-ot-receiver-choose S 1)
        (multiple-value-bind (c0 c1) (base-ot-sender-encrypt y S R m0 m1)
          (let ((result (base-ot-receiver-decrypt x S choice c0 c1)))
            (check (bytes-equal-p result m1) "Base OT choice=1")))))))

;;; ============================================================================
;;; SPDZ Tests
;;; ============================================================================

(deftest test-spdz-share-open
  (let ((prime 65537))
    (multiple-value-bind (alpha mac-shares)
        (generate-mac-key-shares 3 2 :prime prime)
      (let* ((secret 42)
             (shares (spdz-share-secret secret alpha 3 :prime prime))
             (opened (spdz-open shares :prime prime)))
        (check-equal opened secret "SPDZ open")
        (check (spdz-mac-check opened shares mac-shares :prime prime)
               "SPDZ MAC check")))))

(deftest test-spdz-addition
  (let ((prime 65537))
    (multiple-value-bind (alpha mac-shares)
        (generate-mac-key-shares 3 2 :prime prime)
      (declare (ignore mac-shares))
      (let* ((s1 (spdz-share-secret 100 alpha 3 :prime prime))
             (s2 (spdz-share-secret 50 alpha 3 :prime prime))
             (sum (run-spdz-addition s1 s2 :prime prime))
             (opened (spdz-open sum :prime prime)))
        (check-equal opened 150 "SPDZ addition")))))

(deftest test-spdz-multiply-constant
  (let ((prime 65537))
    (multiple-value-bind (alpha mac-shares)
        (generate-mac-key-shares 3 2 :prime prime)
      (declare (ignore mac-shares))
      (let* ((shares (spdz-share-secret 7 alpha 3 :prime prime))
             (scaled (mapcar (lambda (s)
                               (spdz-multiply-by-constant s 6 :prime prime))
                             shares))
             (opened (spdz-open scaled :prime prime)))
        (check-equal opened 42 "SPDZ multiply by constant")))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-all-tests ()
  "Run all tests and report results."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)
  (format t "~&Running cl-mpc tests...~%~%")

  ;; Run tests
  (test-random-bytes)
  (test-integer-bytes-conversion)
  (test-modular-arithmetic)
  (test-sha256)
  (test-aes-encrypt)
  (test-xor-bytes)

  (test-shamir-split-reconstruct)
  (test-shamir-different-subsets)
  (test-share-arithmetic)
  (test-feldman-vss)
  (test-refresh-shares)
  (test-beaver-triple)

  (test-and-circuit)
  (test-or-circuit)
  (test-xor-circuit)
  (test-garbled-circuit-encode-decode)

  (test-ot-1-of-2)
  (test-base-ot)

  (test-spdz-share-open)
  (test-spdz-addition)
  (test-spdz-multiply-constant)

  ;; Report
  (format t "~%========================================~%")
  (format t "Tests: ~A  Passed: ~A  Failed: ~A~%"
          *test-count* *pass-count* *fail-count*)
  (format t "========================================~%")
  (if (zerop *fail-count*)
      (format t "ALL TESTS PASSED~%")
      (format t "SOME TESTS FAILED~%"))
  (values *pass-count* *fail-count* *test-count*))
