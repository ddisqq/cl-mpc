;;;; protocol.lisp - MPC Protocol implementations
;;;; Oblivious Transfer (1-of-2, 1-of-n, Extensions) and SPDZ

(in-package #:cl-mpc)

;;; ============================================================================
;;; Oblivious Transfer Types
;;; ============================================================================

(defstruct ot-sender-state
  "State for OT sender."
  (private-key 0 :type integer)
  (public-key 0 :type integer)
  (messages nil :type list))

(defstruct ot-receiver-state
  "State for OT receiver."
  (choice 0 :type integer)
  (private-key 0 :type integer)
  (blinding nil))

(defstruct ot-message
  "Encrypted messages in OT."
  (ciphertext0 nil)
  (ciphertext1 nil))

;; OT parameters (simplified Diffie-Hellman based)
(defparameter *ot-prime*
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
(defparameter *ot-generator* 2)

;;; ============================================================================
;;; 1-of-2 Oblivious Transfer (Simplified)
;;; ============================================================================

(defun ot-sender-init ()
  "Initialize OT sender. Returns sender state with public key."
  (let* ((sk (random-below *ot-prime*))
         (pk (mpc-mod-expt *ot-generator* sk *ot-prime*)))
    (make-ot-sender-state
     :private-key sk
     :public-key pk)))

(defun ot-receiver-choose (sender-pk choice)
  "Receiver chooses bit CHOICE (0 or 1) and generates blinded public key.
Returns (values receiver-state blinded-pk)."
  (let* ((r (random-below *ot-prime*))
         (gr (mpc-mod-expt *ot-generator* r *ot-prime*))
         ;; If choice=0: send g^r
         ;; If choice=1: send pk * g^r (so sender can't tell which)
         (blinded (if (zerop choice)
                      gr
                      (mod (* sender-pk gr) *ot-prime*))))
    (values (make-ot-receiver-state
             :choice choice
             :private-key r
             :blinding blinded)
            blinded)))

(defun ot-sender-transfer (sender-state receiver-blinded m0 m1)
  "Sender encrypts both messages. Returns ot-message."
  (let* ((sk (ot-sender-state-private-key sender-state))
         ;; k0 = H(blinded^sk)
         (k0-preimage (mpc-mod-expt receiver-blinded sk *ot-prime*))
         (k0 (sha256 (integer-to-bytes k0-preimage 32)))
         ;; k1 = H((blinded / pk)^sk) = H(blinded^sk / pk^sk) = H(blinded^sk / g^(sk*sk))
         ;; Simplified: k1 = H((blinded * g^(-sk))^sk)
         (pk (ot-sender-state-public-key sender-state))
         (pk-inv (mpc-mod-inverse pk *ot-prime*))
         (blinded-adj (mod (* receiver-blinded pk-inv) *ot-prime*))
         (k1-preimage (mpc-mod-expt blinded-adj sk *ot-prime*))
         (k1 (sha256 (integer-to-bytes k1-preimage 32)))
         ;; Encrypt messages (XOR with key, messages must be <= 32 bytes)
         (m0-bytes (if (integerp m0) (integer-to-bytes m0 32) m0))
         (m1-bytes (if (integerp m1) (integer-to-bytes m1 32) m1))
         (c0 (xor-bytes m0-bytes (subseq k0 0 (length m0-bytes))))
         (c1 (xor-bytes m1-bytes (subseq k1 0 (length m1-bytes)))))
    (make-ot-message :ciphertext0 c0 :ciphertext1 c1)))

(defun ot-receiver-decrypt (receiver-state sender-pk ot-msg)
  "Receiver decrypts the chosen message."
  (let* ((choice (ot-receiver-state-choice receiver-state))
         (r (ot-receiver-state-private-key receiver-state))
         ;; Compute shared key: pk^r
         (shared (mpc-mod-expt sender-pk r *ot-prime*))
         (key (sha256 (integer-to-bytes shared 32)))
         ;; Decrypt chosen ciphertext
         (ct (if (zerop choice)
                 (ot-message-ciphertext0 ot-msg)
                 (ot-message-ciphertext1 ot-msg))))
    (xor-bytes ct (subseq key 0 (length ct)))))

;;; ============================================================================
;;; 1-of-n Oblivious Transfer
;;; ============================================================================

(defstruct ot-n-sender-state
  "State for 1-of-n OT sender."
  (private-keys nil :type list)
  (public-keys nil :type list))

(defstruct ot-n-receiver-state
  "State for 1-of-n OT receiver."
  (choice 0 :type integer)
  (private-key 0 :type integer)
  (blinding nil))

(defun ot-n-sender-init (n)
  "Initialize sender for 1-of-n OT with N messages."
  (let ((sks (loop repeat n collect (random-below *ot-prime*)))
        (pks nil))
    (setf pks (mapcar (lambda (sk)
                        (mpc-mod-expt *ot-generator* sk *ot-prime*))
                      sks))
    (make-ot-n-sender-state :private-keys sks :public-keys pks)))

(defun ot-n-receiver-choose (sender-pks choice)
  "Receiver chooses index CHOICE from N options."
  (let* ((r (random-below *ot-prime*))
         (gr (mpc-mod-expt *ot-generator* r *ot-prime*))
         ;; Blend with chosen public key
         (pk-choice (nth choice sender-pks))
         (blinded (mod (* pk-choice gr) *ot-prime*)))
    (values (make-ot-n-receiver-state
             :choice choice
             :private-key r
             :blinding blinded)
            blinded)))

(defun ot-n-sender-transfer (sender-state receiver-blinded messages)
  "Sender encrypts all N messages."
  (let* ((sks (ot-n-sender-state-private-keys sender-state))
         (pks (ot-n-sender-state-public-keys sender-state)))
    (loop for i from 0
          for sk in sks
          for pk in pks
          for msg in messages
          collect (let* ((pk-inv (mpc-mod-inverse pk *ot-prime*))
                         (adjusted (mod (* receiver-blinded pk-inv) *ot-prime*))
                         (shared (mpc-mod-expt adjusted sk *ot-prime*))
                         (key (sha256 (integer-to-bytes shared 32)))
                         (msg-bytes (if (integerp msg)
                                        (integer-to-bytes msg 32)
                                        msg)))
                    (xor-bytes msg-bytes (subseq key 0 (length msg-bytes)))))))

(defun ot-n-receiver-decrypt (receiver-state sender-pks ciphertexts)
  "Receiver decrypts chosen message from N ciphertexts."
  (let* ((choice (ot-n-receiver-state-choice receiver-state))
         (r (ot-n-receiver-state-private-key receiver-state))
         (pk (nth choice sender-pks))
         (shared (mpc-mod-expt pk r *ot-prime*))
         (key (sha256 (integer-to-bytes shared 32)))
         (ct (nth choice ciphertexts)))
    (xor-bytes ct (subseq key 0 (length ct)))))

;;; ============================================================================
;;; Base OT (Chou-Orlandi style)
;;; ============================================================================

(defun base-ot-sender-setup ()
  "Sender generates key pair for base OT."
  (let* ((y (random-below *ot-prime*))
         (S (mpc-mod-expt *ot-generator* y *ot-prime*)))
    (values y S)))

(defun base-ot-receiver-choose (S choice)
  "Receiver chooses bit and sends blinded value.
Returns (values x R) where R is sent to sender."
  (let* ((x (random-below *ot-prime*))
         (R (if (zerop choice)
                (mpc-mod-expt *ot-generator* x *ot-prime*)
                (mod (* S (mpc-mod-expt *ot-generator* x *ot-prime*))
                     *ot-prime*))))
    (values x R choice)))

(defun base-ot-sender-encrypt (y S R m0 m1)
  "Sender encrypts both messages using receiver's R."
  (let* (;; k0 = H(R^y)
         (k0-pre (mpc-mod-expt R y *ot-prime*))
         (k0 (sha256 (integer-to-bytes k0-pre 32)))
         ;; k1 = H((R/S)^y)
         (S-inv (mpc-mod-inverse S *ot-prime*))
         (R-adj (mod (* R S-inv) *ot-prime*))
         (k1-pre (mpc-mod-expt R-adj y *ot-prime*))
         (k1 (sha256 (integer-to-bytes k1-pre 32)))
         ;; Encrypt
         (m0-bytes (if (integerp m0) (integer-to-bytes m0 32) m0))
         (m1-bytes (if (integerp m1) (integer-to-bytes m1 32) m1))
         (c0 (xor-bytes m0-bytes (subseq k0 0 (length m0-bytes))))
         (c1 (xor-bytes m1-bytes (subseq k1 0 (length m1-bytes)))))
    (values c0 c1)))

(defun base-ot-receiver-decrypt (x S choice c0 c1)
  "Receiver decrypts chosen message."
  (let* ((shared (mpc-mod-expt S x *ot-prime*))
         (key (sha256 (integer-to-bytes shared 32)))
         (ct (if (zerop choice) c0 c1)))
    (xor-bytes ct (subseq key 0 (length ct)))))

;;; ============================================================================
;;; OT Extension (IKNP-style simplified)
;;; ============================================================================

(defstruct ot-extension-state
  "State for OT extension."
  (base-ots nil :type list)
  (security-param 128 :type integer)
  (matrix-t nil)
  (delta nil))

(defun ot-extension-init (security-param)
  "Initialize OT extension with base OTs."
  ;; In real implementation, run security-param base OTs
  (make-ot-extension-state
   :security-param security-param
   :base-ots nil
   :matrix-t nil
   :delta nil))

(defun ot-extension-receiver-setup (state n choices)
  "Receiver sets up for N extended OTs with given choices."
  (declare (ignore choices))
  (let* ((kappa (ot-extension-state-security-param state))
         ;; Generate random matrix (n x kappa bits)
         (matrix (loop repeat n
                       collect (get-random-bytes (ceiling kappa 8)))))
    ;; Compute U = matrix XOR (choices * delta)
    ;; Simplified: just return matrix for now
    (setf (ot-extension-state-matrix-t state) matrix)
    ;; Return matrix to send to sender
    matrix))

(defun ot-extension-sender-respond (state receiver-matrix)
  "Sender responds to receiver's matrix."
  (declare (ignore receiver-matrix))
  ;; Simplified implementation
  state)

(defun ot-extension-transfer (state messages-pairs)
  "Transfer messages using extended OT.
MESSAGES-PAIRS: list of (m0 . m1) pairs."
  (let* ((matrix (ot-extension-state-matrix-t state)))
    ;; Encrypt each pair
    (loop for (m0 . m1) in messages-pairs
          for row in matrix
          collect (let* ((k0 (sha256 row))
                         (k1 (sha256 (xor-bytes row
                                                (get-random-bytes (length row)))))
                         (m0-bytes (if (integerp m0)
                                       (integer-to-bytes m0 32)
                                       m0))
                         (m1-bytes (if (integerp m1)
                                       (integer-to-bytes m1 32)
                                       m1)))
                    (cons (xor-bytes m0-bytes (subseq k0 0 (length m0-bytes)))
                          (xor-bytes m1-bytes (subseq k1 0 (length m1-bytes))))))))

;;; ============================================================================
;;; Random OT
;;; ============================================================================

(defun random-ot-sender-init ()
  "Initialize random OT where sender gets two random values."
  (let ((r0 (get-random-bytes 32))
        (r1 (get-random-bytes 32)))
    (values (ot-sender-init) r0 r1)))

(defun random-ot-receiver-choose (sender-pk choice)
  "Receiver chooses which random value to learn."
  (ot-receiver-choose sender-pk choice))

(defun random-ot-complete (sender-state receiver-blinded r0 r1)
  "Complete random OT, sender sends encrypted randoms."
  (ot-sender-transfer sender-state receiver-blinded r0 r1))

;;; ============================================================================
;;; Correlated OT
;;; ============================================================================

(defun correlated-ot-sender-init (delta)
  "Initialize correlated OT where m1 = m0 + delta."
  (let* ((sender (ot-sender-init))
         (m0 (get-random-bytes 32)))
    (values sender m0 delta)))

(defun correlated-ot-receiver-choose (sender-pk choice)
  "Receiver chooses which correlated value to get."
  (ot-receiver-choose sender-pk choice))

(defun correlated-ot-complete (sender-state receiver-blinded m0 delta)
  "Complete correlated OT."
  (let ((m1 (xor-bytes m0 (if (integerp delta)
                              (integer-to-bytes delta 32)
                              delta))))
    (ot-sender-transfer sender-state receiver-blinded m0 m1)))

;;; ============================================================================
;;; Batched OT
;;; ============================================================================

(defun batched-ot-sender-init (n)
  "Initialize batch of N OTs."
  (loop repeat n collect (ot-sender-init)))

(defun batched-ot-receiver-choose (sender-pks choices)
  "Receiver makes choices for batch of OTs."
  (loop for pk in sender-pks
        for choice in choices
        collect (multiple-value-list (ot-receiver-choose pk choice))))

(defun batched-ot-transfer (sender-states receiver-blindeds message-pairs)
  "Transfer batch of message pairs."
  (loop for state in sender-states
        for blinded in receiver-blindeds
        for (m0 . m1) in message-pairs
        collect (ot-sender-transfer state blinded m0 m1)))

;;; ============================================================================
;;; SPDZ Protocol Types
;;; ============================================================================

(defstruct spdz-share
  "A share in SPDZ with MAC."
  (value 0 :type integer)
  (mac 0 :type integer))

(defstruct spdz-party
  "A party in SPDZ protocol."
  (id 0 :type integer)
  (mac-key-share 0 :type integer)
  (shares nil :type list)  ; Hash table of variable -> spdz-share
  (prime +secp256k1-order+))

;;; ============================================================================
;;; SPDZ MAC Operations
;;; ============================================================================

(defun generate-mac-key-shares (n threshold &key (prime +secp256k1-order+))
  "Generate shares of the global MAC key alpha."
  (let ((alpha (random-below prime)))
    (values alpha (split-secret alpha n threshold :prime prime))))

(defun spdz-share-secret (secret alpha n &key (prime +secp256k1-order+))
  "Create SPDZ shares of a secret with MAC.
Returns list of spdz-share."
  ;; Simple additive sharing
  (let* ((shares (loop repeat (1- n)
                       collect (random-below prime)))
         (last-share (mod (- secret (reduce #'+ shares)) prime))
         (all-shares (append shares (list last-share)))
         ;; MAC = alpha * secret
         (mac (* alpha secret))
         (mac-shares (loop repeat (1- n)
                           collect (random-below prime)))
         (last-mac (mod (- mac (reduce #'+ mac-shares)) prime))
         (all-macs (append mac-shares (list last-mac))))
    (loop for v in all-shares
          for m in all-macs
          collect (make-spdz-share :value v :mac m))))

;;; ============================================================================
;;; SPDZ Linear Operations (Local)
;;; ============================================================================

(defun spdz-add (share1 share2 &key (prime +secp256k1-order+))
  "Add two SPDZ shares locally."
  (make-spdz-share
   :value (mpc-mod-add (spdz-share-value share1)
                       (spdz-share-value share2)
                       prime)
   :mac (mpc-mod-add (spdz-share-mac share1)
                     (spdz-share-mac share2)
                     prime)))

(defun spdz-subtract (share1 share2 &key (prime +secp256k1-order+))
  "Subtract two SPDZ shares locally."
  (make-spdz-share
   :value (mpc-mod-sub (spdz-share-value share1)
                       (spdz-share-value share2)
                       prime)
   :mac (mpc-mod-sub (spdz-share-mac share1)
                     (spdz-share-mac share2)
                     prime)))

(defun spdz-multiply-by-constant (share c &key (prime +secp256k1-order+))
  "Multiply SPDZ share by public constant."
  (make-spdz-share
   :value (mpc-mod-mul (spdz-share-value share) c prime)
   :mac (mpc-mod-mul (spdz-share-mac share) c prime)))

;;; ============================================================================
;;; SPDZ Multiplication (Requires Beaver Triple)
;;; ============================================================================

(defstruct spdz-beaver-triple
  "Beaver triple with SPDZ shares."
  (a nil)  ; spdz-share of random a
  (b nil)  ; spdz-share of random b
  (c nil)) ; spdz-share of c = a*b

(defun spdz-multiply (x-share y-share triple &key (prime +secp256k1-order+))
  "Start multiplication using Beaver triple.
Returns shares of (x-a) and (y-b) to be opened."
  (let ((d-share (spdz-subtract x-share (spdz-beaver-triple-a triple) :prime prime))
        (e-share (spdz-subtract y-share (spdz-beaver-triple-b triple) :prime prime)))
    (values d-share e-share)))

(defun spdz-multiply-finish (d e triple party-id num-parties &key (prime +secp256k1-order+))
  "Finish multiplication after d and e are opened.
z = c + e*a + d*b + d*e (where d*e is added by party 1 only)."
  (declare (ignore num-parties))
  (let* ((c (spdz-beaver-triple-c triple))
         (a (spdz-beaver-triple-a triple))
         (b (spdz-beaver-triple-b triple))
         ;; e*a
         (ea (spdz-multiply-by-constant a e :prime prime))
         ;; d*b
         (db (spdz-multiply-by-constant b d :prime prime))
         ;; c + e*a + d*b
         (result (spdz-add c (spdz-add ea db :prime prime) :prime prime)))
    ;; Only party 1 adds d*e
    (if (= party-id 1)
        (let ((de (mpc-mod-mul d e prime)))
          (make-spdz-share
           :value (mpc-mod-add (spdz-share-value result) de prime)
           :mac (spdz-share-mac result)))
        result)))

;;; ============================================================================
;;; SPDZ Opening and MAC Check
;;; ============================================================================

(defun spdz-open (shares)
  "Open a secret by summing all shares. Returns opened value."
  (reduce #'+ (mapcar #'spdz-share-value shares)))

(defun spdz-mac-check (opened-value shares mac-key-shares &key (prime +secp256k1-order+))
  "Verify MAC on opened value.
Check: sum(mac_i) = alpha * opened_value."
  (let* ((mac-sum (mod (reduce #'+ (mapcar #'spdz-share-mac shares)) prime))
         (alpha-value (mod (reduce #'+ (mapcar #'secret-share-value mac-key-shares)) prime))
         (expected (mpc-mod-mul alpha-value opened-value prime)))
    (= mac-sum expected)))

(defun spdz-open-with-check (shares mac-key-shares &key (prime +secp256k1-order+))
  "Open value and verify MAC. Returns value or signals error."
  (let ((opened (spdz-open shares)))
    (unless (spdz-mac-check opened shares mac-key-shares :prime prime)
      (error "SPDZ MAC verification failed - possible cheating detected"))
    opened))

;;; ============================================================================
;;; SPDZ Protocol Execution
;;; ============================================================================

(defun run-spdz-addition (shares1 shares2 &key (prime +secp256k1-order+))
  "Run SPDZ addition protocol.
Each party computes locally, no communication needed."
  (loop for s1 in shares1
        for s2 in shares2
        collect (spdz-add s1 s2 :prime prime)))

(defun run-spdz-multiplication (shares1 shares2 triples n &key (prime +secp256k1-order+))
  "Run SPDZ multiplication protocol.
Requires one Beaver triple per multiplication."
  ;; Step 1: Compute d = x - a and e = y - b locally
  (let ((d-shares '())
        (e-shares '()))
    (loop for s1 in shares1
          for s2 in shares2
          for triple in triples
          do (multiple-value-bind (d e)
                 (spdz-multiply s1 s2 triple :prime prime)
               (push d d-shares)
               (push e e-shares)))
    (setf d-shares (nreverse d-shares))
    (setf e-shares (nreverse e-shares))
    ;; Step 2: Open d and e (in real protocol, broadcast and combine)
    (let ((d (mod (reduce #'+ (mapcar #'spdz-share-value d-shares)) prime))
          (e (mod (reduce #'+ (mapcar #'spdz-share-value e-shares)) prime)))
      ;; Step 3: Each party computes their share of result
      (loop for i from 1 to n
            for triple in triples
            collect (spdz-multiply-finish d e triple i n :prime prime)))))

(defun run-spdz-circuit (circuit inputs mac-key-shares &key (prime +secp256k1-order+))
  "Run a circuit in SPDZ.
CIRCUIT: list of (:add var1 var2 result) or (:mul var1 var2 result triple)
INPUTS: hash table var -> list of spdz-shares"
  (let ((vars (make-hash-table :test 'equal)))
    ;; Copy inputs
    (maphash (lambda (k v) (setf (gethash k vars) v)) inputs)
    ;; Process gates
    (dolist (gate circuit)
      (let ((op (first gate))
            (in1 (second gate))
            (in2 (third gate))
            (out (fourth gate)))
        (case op
          (:add
           (setf (gethash out vars)
                 (run-spdz-addition (gethash in1 vars)
                                    (gethash in2 vars)
                                    :prime prime)))
          (:mul
           (let ((triple (fifth gate))
                 (n (length (gethash in1 vars))))
             (setf (gethash out vars)
                   (run-spdz-multiplication (gethash in1 vars)
                                            (gethash in2 vars)
                                            (list triple)
                                            n
                                            :prime prime))))
          (:const
           ;; Multiply by constant
           (let ((c in2))
             (setf (gethash out vars)
                   (mapcar (lambda (s)
                             (spdz-multiply-by-constant s c :prime prime))
                           (gethash in1 vars)))))
          (:open
           ;; Open variable
           (let ((shares (gethash in1 vars)))
             (setf (gethash out vars)
                   (spdz-open-with-check shares mac-key-shares :prime prime)))))))
    vars))
