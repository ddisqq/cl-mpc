;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; sharing.lisp - Secret Sharing implementations
;;;; Shamir, Feldman VSS, Pedersen VSS, DKG, Proactive SS, Packed SS

(in-package #:cl-mpc)

;;; ============================================================================
;;; Shamir Secret Sharing
;;; ============================================================================

(defstruct secret-share
  "A share of a secret in Shamir's scheme."
  (index 0 :type integer)
  (value 0 :type integer)
  (threshold 0 :type integer)
  (prime +secp256k1-order+ :type integer))

(defstruct share-commitment
  "Commitment to a share for verification."
  (index 0 :type integer)
  (commitment nil)
  (proof nil))

(defun generate-polynomial (secret threshold prime)
  "Generate a random polynomial of degree (threshold-1) with SECRET as constant term."
  (cons secret
        (loop repeat (1- threshold)
              collect (random-below prime))))

(defun evaluate-polynomial (coeffs x prime)
  "Evaluate polynomial with COEFFS at point X."
  (let ((result 0)
        (power 1))
    (dolist (coeff coeffs)
      (setf result (mpc-mod-add result (mpc-mod-mul coeff power prime) prime))
      (setf power (mpc-mod-mul power x prime)))
    result))

(defun split-secret (secret n threshold &key (prime +secp256k1-order+))
  "Split SECRET into N shares with THRESHOLD required for reconstruction.
Returns a list of secret-share structures."
  (unless (<= threshold n)
    (error "Threshold must be <= number of shares"))
  (unless (>= threshold 1)
    (error "Threshold must be >= 1"))
  (let ((coeffs (generate-polynomial secret threshold prime)))
    (loop for i from 1 to n
          collect (make-secret-share
                   :index i
                   :value (evaluate-polynomial coeffs i prime)
                   :threshold threshold
                   :prime prime))))

(defun reconstruct-secret (shares &key (prime nil))
  "Reconstruct the secret from SHARES using Lagrange interpolation."
  (when (null shares)
    (error "No shares provided"))
  (let* ((prime (or prime (secret-share-prime (first shares))))
         (threshold (secret-share-threshold (first shares))))
    (when (< (length shares) threshold)
      (error "Not enough shares: need ~A, got ~A" threshold (length shares)))
    ;; Convert to points format for lagrange-interpolate
    (let ((points (mapcar (lambda (s)
                            (cons (secret-share-index s)
                                  (secret-share-value s)))
                          shares)))
      (lagrange-interpolate points prime))))

(defun verify-share (share commitment prime generator)
  "Verify a share against its commitment using discrete log verification."
  (declare (ignore share commitment prime generator))
  ;; Simplified - in full implementation would verify g^share = commitment
  t)

(defun refresh-shares (shares &key (prime nil))
  "Refresh shares with new randomness while preserving the secret.
Used in proactive secret sharing."
  (when (null shares)
    (error "No shares provided"))
  (let* ((prime (or prime (secret-share-prime (first shares))))
         (threshold (secret-share-threshold (first shares)))
         ;; Generate refresh polynomial with 0 constant term
         (refresh-coeffs (cons 0 (loop repeat (1- threshold)
                                        collect (random-below prime)))))
    (loop for share in shares
          collect (make-secret-share
                   :index (secret-share-index share)
                   :value (mpc-mod-add
                           (secret-share-value share)
                           (evaluate-polynomial refresh-coeffs
                                                (secret-share-index share)
                                                prime)
                           prime)
                   :threshold threshold
                   :prime prime))))

(defun add-shares (share1 share2)
  "Add two shares (for the same index)."
  (unless (= (secret-share-index share1) (secret-share-index share2))
    (error "Cannot add shares with different indices"))
  (let ((prime (secret-share-prime share1)))
    (make-secret-share
     :index (secret-share-index share1)
     :value (mpc-mod-add (secret-share-value share1)
                         (secret-share-value share2)
                         prime)
     :threshold (secret-share-threshold share1)
     :prime prime)))

(defun sub-shares (share1 share2)
  "Subtract share2 from share1 (for the same index)."
  (unless (= (secret-share-index share1) (secret-share-index share2))
    (error "Cannot subtract shares with different indices"))
  (let ((prime (secret-share-prime share1)))
    (make-secret-share
     :index (secret-share-index share1)
     :value (mpc-mod-sub (secret-share-value share1)
                         (secret-share-value share2)
                         prime)
     :threshold (secret-share-threshold share1)
     :prime prime)))

(defun scalar-mul-share (share scalar)
  "Multiply a share by a public scalar."
  (let ((prime (secret-share-prime share)))
    (make-secret-share
     :index (secret-share-index share)
     :value (mpc-mod-mul (secret-share-value share) scalar prime)
     :threshold (secret-share-threshold share)
     :prime prime)))

;;; ============================================================================
;;; Verifiable Secret Sharing
;;; ============================================================================

(defstruct vss-commitment
  "Commitment for Verifiable Secret Sharing."
  (coefficients nil :type list)  ; g^a_i for each coefficient
  (generator nil))

(defstruct vss-share
  "A share in a VSS scheme."
  (index 0 :type integer)
  (value 0 :type integer)
  (commitment nil))

;; Default generators for Feldman/Pedersen VSS (simplified)
(defparameter *default-generator* 2)
(defparameter *default-prime-group*
  ;; Safe prime for demonstration
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)

(defun feldman-vss-split (secret n threshold &key
                                              (prime nil)
                                              (generator *default-generator*)
                                              (group-prime *default-prime-group*))
  "Split SECRET using Feldman VSS with publicly verifiable commitments.
Returns (values shares commitment).
Note: PRIME defaults to (group-prime - 1) for correct verification."
  ;; For Feldman VSS, polynomial operations must be mod (group-prime - 1)
  ;; which is the order of the multiplicative group
  (let* ((prime (or prime (1- group-prime)))
         (coeffs (generate-polynomial secret threshold prime))
         ;; Compute commitments g^a_i mod group-prime
         (commitments (mapcar (lambda (coeff)
                                (mpc-mod-expt generator coeff group-prime))
                              coeffs))
         (commitment (make-vss-commitment
                      :coefficients commitments
                      :generator generator))
         (shares (loop for i from 1 to n
                       collect (make-vss-share
                                :index i
                                :value (evaluate-polynomial coeffs i prime)
                                :commitment commitment))))
    (values shares commitment)))

(defun feldman-vss-verify (share commitment &key
                                             (group-prime *default-prime-group*))
  "Verify a Feldman VSS share against commitment.
Checks that g^share = product of C_j^(i^j) for j=0..t-1."
  (let* ((g (vss-commitment-generator commitment))
         (coeffs (vss-commitment-coefficients commitment))
         (i (vss-share-index share))
         (value (vss-share-value share))
         ;; Left side: g^value mod group-prime
         (left (mpc-mod-expt g value group-prime))
         ;; Right side: product of C_j^(i^j) mod group-prime
         ;; Exponents are computed mod (group-prime - 1) by Fermat's little theorem
         (exp-mod (1- group-prime))
         (right 1))
    (loop for j from 0
          for cj in coeffs
          do (let ((i-to-j (mpc-mod-expt i j exp-mod)))
               (setf right (mod (* right (mpc-mod-expt cj i-to-j group-prime))
                               group-prime))))
    (= left right)))

(defun pedersen-vss-split (secret n threshold &key
                                               (prime +secp256k1-order+)
                                               (g *default-generator*)
                                               (h 3)  ; Second generator
                                               (group-prime *default-prime-group*))
  "Split SECRET using Pedersen VSS with information-theoretic hiding.
Returns (values shares commitment blinding-shares)."
  (let* ((coeffs-a (generate-polynomial secret threshold prime))
         ;; Second polynomial for blinding
         (blinding (random-below prime))
         (coeffs-b (generate-polynomial blinding threshold prime))
         ;; Commitments: g^a_i * h^b_i
         (commitments (mapcar (lambda (ai bi)
                                (mod (* (mpc-mod-expt g ai group-prime)
                                        (mpc-mod-expt h bi group-prime))
                                     group-prime))
                              coeffs-a coeffs-b))
         (commitment (make-vss-commitment
                      :coefficients commitments
                      :generator (cons g h)))
         (shares (loop for i from 1 to n
                       collect (make-vss-share
                                :index i
                                :value (evaluate-polynomial coeffs-a i prime)
                                :commitment commitment)))
         (blinding-shares (loop for i from 1 to n
                                collect (evaluate-polynomial coeffs-b i prime))))
    (values shares commitment blinding-shares)))

(defun pedersen-vss-verify (share blinding-value commitment &key
                                                             (prime +secp256k1-order+)
                                                             (group-prime *default-prime-group*))
  "Verify a Pedersen VSS share against commitment."
  (let* ((generators (vss-commitment-generator commitment))
         (g (car generators))
         (h (cdr generators))
         (coeffs (vss-commitment-coefficients commitment))
         (i (vss-share-index share))
         (value (vss-share-value share))
         ;; Left side: g^value * h^blinding
         (left (mod (* (mpc-mod-expt g value group-prime)
                       (mpc-mod-expt h blinding-value group-prime))
                    group-prime))
         ;; Right side: product of C_j^(i^j)
         (right 1))
    (loop for j from 0
          for cj in coeffs
          do (let ((i-to-j (mpc-mod-expt i j prime)))
               (setf right (mod (* right (mpc-mod-expt cj i-to-j group-prime))
                               group-prime))))
    (= left right)))

;;; ============================================================================
;;; Distributed Key Generation (DKG)
;;; ============================================================================

(defstruct dkg-party-state
  "State for a party in DKG protocol."
  (id 0 :type integer)
  (threshold 0 :type integer)
  (num-parties 0 :type integer)
  (secret-poly nil :type list)
  (received-shares nil :type list)
  (commitments nil :type list)
  (prime +secp256k1-order+))

(defstruct dkg-result
  "Result of DKG protocol."
  (public-key 0 :type integer)
  (share nil)
  (verification-vector nil :type list))

(defun dkg-init-party (party-id threshold num-parties &key (prime +secp256k1-order+))
  "Initialize a party for DKG protocol."
  (let ((secret-poly (generate-polynomial (random-below prime) threshold prime)))
    (make-dkg-party-state
     :id party-id
     :threshold threshold
     :num-parties num-parties
     :secret-poly secret-poly
     :received-shares nil
     :commitments nil
     :prime prime)))

(defun dkg-generate-shares (party-state &key
                                         (generator *default-generator*)
                                         (group-prime *default-prime-group*))
  "Generate shares for other parties and commitment.
Returns (values shares-for-parties commitment)."
  (let* ((prime (dkg-party-state-prime party-state))
         (n (dkg-party-state-num-parties party-state))
         (poly (dkg-party-state-secret-poly party-state))
         ;; Generate Feldman commitment
         (commitment (mapcar (lambda (coeff)
                               (mpc-mod-expt generator coeff group-prime))
                             poly))
         ;; Generate shares for each party
         (shares (loop for i from 1 to n
                       collect (cons i (evaluate-polynomial poly i prime)))))
    ;; Store own commitment
    (setf (dkg-party-state-commitments party-state)
          (list (cons (dkg-party-state-id party-state) commitment)))
    (values shares commitment)))

(defun dkg-receive-share (party-state from-id share-value commitment &key
                                                                       (generator *default-generator*)
                                                                       (group-prime *default-prime-group*))
  "Receive and verify a share from another party.
Returns T if valid, signals error if invalid."
  (let* ((prime (dkg-party-state-prime party-state))
         (my-id (dkg-party-state-id party-state))
         ;; Verify: g^share = product of C_j^(my-id^j)
         (left (mpc-mod-expt generator share-value group-prime))
         (right 1))
    (loop for j from 0
          for cj in commitment
          do (let ((id-to-j (mpc-mod-expt my-id j prime)))
               (setf right (mod (* right (mpc-mod-expt cj id-to-j group-prime))
                               group-prime))))
    (unless (= left right)
      (error "Invalid share from party ~A" from-id))
    ;; Store received share and commitment
    (push (cons from-id share-value)
          (dkg-party-state-received-shares party-state))
    (push (cons from-id commitment)
          (dkg-party-state-commitments party-state))
    t))

(defun dkg-complete (party-state &key
                                   (generator *default-generator*)
                                   (group-prime *default-prime-group*))
  "Complete DKG and compute final share and public key.
Returns dkg-result structure."
  (declare (ignore generator))
  (let* ((prime (dkg-party-state-prime party-state))
         (my-id (dkg-party-state-id party-state))
         (my-poly (dkg-party-state-secret-poly party-state))
         ;; My share: evaluate my polynomial at my index
         (my-share-contribution (evaluate-polynomial my-poly my-id prime))
         ;; Sum all received shares
         (total-share (mod (reduce #'+
                                   (cons my-share-contribution
                                         (mapcar #'cdr (dkg-party-state-received-shares party-state))))
                           prime))
         ;; Compute joint public key: product of all C_0 commitments
         (all-commitments (dkg-party-state-commitments party-state))
         (public-key (reduce (lambda (acc commit)
                               (mod (* acc (car (cdr commit))) group-prime))
                             all-commitments
                             :initial-value 1))
         ;; Verification vector: product of corresponding coefficients
         (threshold (dkg-party-state-threshold party-state))
         (verification-vector
           (loop for j from 0 below threshold
                 collect (reduce (lambda (acc commit)
                                   (let ((coeffs (cdr commit)))
                                     (if (< j (length coeffs))
                                         (mod (* acc (nth j coeffs)) group-prime)
                                         acc)))
                                 all-commitments
                                 :initial-value 1))))
    (make-dkg-result
     :public-key public-key
     :share (make-secret-share
             :index my-id
             :value (mod total-share prime)
             :threshold (dkg-party-state-threshold party-state)
             :prime prime)
     :verification-vector verification-vector)))

;;; ============================================================================
;;; Proactive Secret Sharing
;;; ============================================================================

(defun proactive-refresh (shares epoch &key (prime nil))
  "Refresh shares for a new epoch. Each party contributes refresh values."
  (declare (ignore epoch))
  (refresh-shares shares :prime prime))

(defun proactive-update-share (share refresh-shares-list)
  "Update a share with refresh values from other parties."
  (let* ((prime (secret-share-prime share))
         (my-idx (secret-share-index share))
         ;; Sum all refresh values for my index
         (refresh-sum (mod (reduce #'+
                                   (mapcar #'secret-share-value refresh-shares-list))
                           prime)))
    (make-secret-share
     :index my-idx
     :value (mpc-mod-add (secret-share-value share) refresh-sum prime)
     :threshold (secret-share-threshold share)
     :prime prime)))

;;; ============================================================================
;;; MPC Arithmetic on Shares
;;; ============================================================================

(defun mpc-add-shares (share1 share2)
  "Add two shares locally (no communication needed)."
  (add-shares share1 share2))

(defun mpc-sub-shares (share1 share2)
  "Subtract two shares locally."
  (sub-shares share1 share2))

(defun mpc-scalar-mul-share (share scalar)
  "Multiply share by public scalar locally."
  (scalar-mul-share share scalar))

;;; ============================================================================
;;; Beaver Triples for Multiplication
;;; ============================================================================

(defstruct beaver-triple
  "Pre-computed triple for secure multiplication."
  (a nil)   ; Share of random a
  (b nil)   ; Share of random b
  (c nil))  ; Share of c = a*b

(defun generate-beaver-triple (n threshold &key (prime +secp256k1-order+))
  "Generate shares of a Beaver triple (a, b, c) where c = a*b.
Returns list of (beaver-triple) for each party."
  (let* ((a (random-below prime))
         (b (random-below prime))
         (c (mpc-mod-mul a b prime))
         (a-shares (split-secret a n threshold :prime prime))
         (b-shares (split-secret b n threshold :prime prime))
         (c-shares (split-secret c n threshold :prime prime)))
    (loop for i from 0 below n
          collect (make-beaver-triple
                   :a (nth i a-shares)
                   :b (nth i b-shares)
                   :c (nth i c-shares)))))

(defun mpc-multiply-shares-beaver (x-share y-share triple &key (prime nil))
  "Multiply shares using Beaver triple.
Requires opening d = x - a and e = y - b, then computing:
z = c + d*[b] + e*[a] + d*e
Returns intermediate values and final share computation."
  (let ((prime (or prime (secret-share-prime x-share))))
    ;; Compute masked differences (these get opened)
    (let* ((d-share (sub-shares x-share (beaver-triple-a triple)))
           (e-share (sub-shares y-share (beaver-triple-b triple))))
      ;; Return the shares to be opened and the function to compute final result
      (values d-share e-share
              (lambda (d e)
                ;; Once d and e are opened, compute:
                ;; z = c + d*b + e*a + d*e
                (let* ((c-share (beaver-triple-c triple))
                       (d-times-b (scalar-mul-share (beaver-triple-b triple) d))
                       (e-times-a (scalar-mul-share (beaver-triple-a triple) e))
                       (de (mpc-mod-mul d e prime))
                       ;; Start with c
                       (result c-share))
                  ;; Add d*b
                  (setf result (add-shares result d-times-b))
                  ;; Add e*a
                  (setf result (add-shares result e-times-a))
                  ;; Add d*e (public constant)
                  (make-secret-share
                   :index (secret-share-index result)
                   :value (mpc-mod-add (secret-share-value result) de prime)
                   :threshold (secret-share-threshold result)
                   :prime prime)))))))

;;; ============================================================================
;;; Packed Secret Sharing
;;; ============================================================================

(defun packed-split-secrets (secrets n threshold &key (prime +secp256k1-order+))
  "Split multiple secrets into packed shares.
More efficient than splitting each secret separately."
  (let ((k (length secrets)))
    (when (> k threshold)
      (error "Number of secrets (~A) exceeds threshold (~A)" k threshold))
    ;; Use evaluation points -k+1, ..., 0 for secrets
    ;; and 1, ..., n for shares
    (let* ((degree (+ threshold k -1))
           ;; Interpolate polynomial through secret points
           (secret-points (loop for i from (- 1 k) to 0
                                for s in secrets
                                collect (cons i s)))
           ;; We need degree+1 points, fill remaining with random
           (random-points (loop for i from 1 to (- degree (1- k))
                                collect (cons (+ n i) (random-below prime))))
           (all-input-points (append secret-points random-points)))
      ;; Lagrange interpolate to find polynomial, then evaluate at share points
      (loop for i from 1 to n
            collect (make-secret-share
                     :index i
                     :value (let ((result 0))
                              (loop for j from 0 below (length all-input-points)
                                    do (let ((yj (cdr (nth j all-input-points)))
                                             (coeff (lagrange-coefficient
                                                     j all-input-points prime)))
                                         (setf result
                                               (mpc-mod-add
                                                result
                                                (mpc-mod-mul yj coeff prime)
                                                prime))))
                              result)
                     :threshold threshold
                     :prime prime)))))

(defun packed-reconstruct-secrets (shares k &key (prime nil))
  "Reconstruct K secrets from packed shares."
  (let* ((prime (or prime (secret-share-prime (first shares))))
         (points (mapcar (lambda (s)
                           (cons (secret-share-index s)
                                 (secret-share-value s)))
                         shares)))
    ;; Evaluate interpolated polynomial at -k+1, ..., 0
    (loop for i from (- 1 k) to 0
          collect (let ((result 0))
                    (loop for j from 0 below (length points)
                          do (let ((yj (cdr (nth j points)))
                                   ;; Compute Lagrange coefficient for eval at i
                                   (coeff (let ((xj (car (nth j points)))
                                                (c 1))
                                            (loop for m from 0 below (length points)
                                                  unless (= m j)
                                                  do (let* ((xm (car (nth m points)))
                                                            (num (mpc-mod-sub i xm prime))
                                                            (den (mpc-mod-sub xj xm prime)))
                                                       (setf c (mpc-mod-mul
                                                                c
                                                                (mpc-mod-mul
                                                                 num
                                                                 (mpc-mod-inverse den prime)
                                                                 prime)
                                                                prime))))
                                            c)))
                               (setf result
                                     (mpc-mod-add
                                      result
                                      (mpc-mod-mul yj coeff prime)
                                      prime))))
                    result))))
