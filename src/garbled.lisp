;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; garbled.lisp - Garbled Circuits implementation
;;;; Yao's protocol with Free XOR, Half-Gates, and Row Reduction optimizations

(in-package #:cl-mpc)

;;; ============================================================================
;;; Wire Labels
;;; ============================================================================

(defstruct wire-label
  "A wire label in a garbled circuit (128-bit value + pointer bit)."
  (value nil :type (or null (simple-array (unsigned-byte 8) (16))))
  (pointer-bit 0 :type bit))

(defun make-random-wire-label ()
  "Generate a random 128-bit wire label."
  (make-wire-label
   :value (get-random-bytes +wire-label-bytes+)
   :pointer-bit (random 2)))

(defun wire-label-xor (label1 label2)
  "XOR two wire labels."
  (make-wire-label
   :value (xor-bytes (wire-label-value label1) (wire-label-value label2))
   :pointer-bit (logxor (wire-label-pointer-bit label1)
                        (wire-label-pointer-bit label2))))

;;; ============================================================================
;;; Garbled Wires and Gates
;;; ============================================================================

(defstruct garbled-wire
  "A wire in a garbled circuit with both labels."
  (id 0 :type integer)
  (label0 nil)  ; Label for 0
  (label1 nil)) ; Label for 1

(defstruct garbled-gate
  "A garbled gate with encrypted truth table."
  (id 0 :type integer)
  (type :and :type keyword)  ; :and, :or, :xor, :not
  (input-wires nil :type list)
  (output-wire 0 :type integer)
  (table nil :type list))  ; Encrypted truth table (4 entries, or fewer with optimizations)

(defstruct garbled-circuit
  "A complete garbled circuit."
  (gates nil :type list)
  (input-wires nil :type list)
  (output-wires nil :type list)
  (wire-labels nil)  ; Hash table: wire-id -> garbled-wire
  (global-offset nil)  ; For Free XOR optimization
  (decoding-info nil)) ; Output wire decoding

;;; ============================================================================
;;; Basic Wire Label Generation
;;; ============================================================================

(defun generate-wire-labels (wire-id &optional global-offset)
  "Generate labels for a wire. If global-offset provided, use Free XOR."
  (if global-offset
      ;; Free XOR: label1 = label0 XOR global-offset
      (let* ((label0 (make-random-wire-label))
             (label1 (wire-label-xor label0 global-offset)))
        (make-garbled-wire
         :id wire-id
         :label0 label0
         :label1 label1))
      ;; Standard: two independent random labels with opposite pointer bits
      ;; Point-and-permute requires label0 and label1 to have different pointer bits
      (let* ((label0 (make-random-wire-label))
             (label1 (make-random-wire-label)))
        ;; Ensure opposite pointer bits for proper point-and-permute
        (setf (wire-label-pointer-bit label1)
              (logxor 1 (wire-label-pointer-bit label0)))
        (make-garbled-wire
         :id wire-id
         :label0 label0
         :label1 label1))))

(defun generate-global-offset ()
  "Generate global offset for Free XOR. LSB must be 1."
  (let ((offset (make-random-wire-label)))
    ;; Ensure LSB is 1 for point-and-permute
    (setf (aref (wire-label-value offset) 15)
          (logior (aref (wire-label-value offset) 15) 1))
    (setf (wire-label-pointer-bit offset) 1)
    offset))

;;; ============================================================================
;;; Encryption for Garbled Tables
;;; ============================================================================

(defun garble-encrypt (key1 key2 gate-id row-index plaintext)
  "Encrypt plaintext using double-key cipher with tweak.
Embeds pointer-bit into the encrypted data."
  (let* ((tweak (logior (ash gate-id 2) row-index))
         (combined-key (xor-bytes (wire-label-value key1)
                                   (wire-label-value key2)))
         (derived-key (hash-to-key combined-key tweak))
         ;; Copy plaintext value and embed pointer-bit in LSB of last byte
         (pt-with-pointer (copy-seq (wire-label-value plaintext))))
    ;; Set LSB of last byte to pointer-bit
    (setf (aref pt-with-pointer 15)
          (logior (logand (aref pt-with-pointer 15) #xFE)
                  (wire-label-pointer-bit plaintext)))
    (xor-bytes (aes-encrypt-block derived-key derived-key)
               pt-with-pointer)))

(defun garble-decrypt (key1 key2 gate-id row-index ciphertext)
  "Decrypt ciphertext using double-key cipher with tweak."
  (let* ((tweak (logior (ash gate-id 2) row-index))
         (combined-key (xor-bytes (wire-label-value key1)
                                   (wire-label-value key2)))
         (derived-key (hash-to-key combined-key tweak)))
    (xor-bytes (aes-encrypt-block derived-key derived-key)
               ciphertext)))

;;; ============================================================================
;;; Standard Gate Garbling
;;; ============================================================================

(defun garble-gate-standard (gate-type in1 in2 out gate-id)
  "Garble a gate using standard 4-row table with point-and-permute."
  (let* ((truth-table (case gate-type
                        (:and '((0 0 0) (0 1 0) (1 0 0) (1 1 1)))
                        (:or  '((0 0 0) (0 1 1) (1 0 1) (1 1 1)))
                        (:xor '((0 0 0) (0 1 1) (1 0 1) (1 1 0)))
                        (:nand '((0 0 1) (0 1 1) (1 0 1) (1 1 0)))
                        (:nor '((0 0 1) (0 1 0) (1 0 0) (1 1 0)))))
         ;; Pre-compute pointer bits for each label
         (p0-in1 (wire-label-pointer-bit (garbled-wire-label0 in1)))
         (p1-in1 (wire-label-pointer-bit (garbled-wire-label1 in1)))
         (p0-in2 (wire-label-pointer-bit (garbled-wire-label0 in2)))
         (p1-in2 (wire-label-pointer-bit (garbled-wire-label1 in2)))
         ;; Create a 4-element table indexed by row-idx (0-3)
         (table (make-array 4 :initial-element nil)))
    ;; Generate permuted table entries
    (dolist (row truth-table)
      (let* ((a (first row))
             (b (second row))
             (c (third row))
             (key1 (if (zerop a)
                       (garbled-wire-label0 in1)
                       (garbled-wire-label1 in1)))
             (key2 (if (zerop b)
                       (garbled-wire-label0 in2)
                       (garbled-wire-label1 in2)))
             (plaintext (if (zerop c)
                            (garbled-wire-label0 out)
                            (garbled-wire-label1 out)))
             ;; Row index based on pointer bits of the actual keys used
             (p1 (if (zerop a) p0-in1 p1-in1))
             (p2 (if (zerop b) p0-in2 p1-in2))
             (row-idx (logior (ash p1 1) p2))
             (ciphertext (garble-encrypt key1 key2 gate-id row-idx plaintext)))
        (setf (aref table row-idx) ciphertext)))
    ;; Convert to alist format
    (loop for i from 0 below 4
          when (aref table i)
          collect (cons i (aref table i)))))

;;; ============================================================================
;;; Free XOR Optimization
;;; ============================================================================

(defun garble-xor-gate (in1 in2 out global-offset)
  "Garble XOR gate using Free XOR - no table needed!
Output label = in1 XOR in2."
  (declare (ignore global-offset))
  ;; With Free XOR, XOR gates are free:
  ;; out0 = in1_0 XOR in2_0
  ;; out1 = in1_0 XOR in2_1 = in1_0 XOR in2_0 XOR offset = out0 XOR offset
  (let ((out0 (wire-label-xor (garbled-wire-label0 in1)
                              (garbled-wire-label0 in2)))
        (out1 (wire-label-xor (garbled-wire-label0 in1)
                              (garbled-wire-label1 in2))))
    (setf (garbled-wire-label0 out) out0)
    (setf (garbled-wire-label1 out) out1))
  ;; Return empty table (free!)
  nil)

;;; ============================================================================
;;; Half-Gates Optimization for AND
;;; ============================================================================

(defun garble-and-gate-half-gates (in1 in2 out gate-id global-offset)
  "Garble AND gate using half-gates optimization (2 ciphertexts instead of 4)."
  (let* ((pa (wire-label-pointer-bit (garbled-wire-label0 in1)))
         (pb (wire-label-pointer-bit (garbled-wire-label0 in2)))
         ;; Hash computations
         (h-a0 (hash-to-key (wire-label-value (garbled-wire-label0 in1))
                            (logior (ash gate-id 1) 0)))
         (h-a1 (hash-to-key (wire-label-value (garbled-wire-label1 in1))
                            (logior (ash gate-id 1) 0)))
         (h-b0 (hash-to-key (wire-label-value (garbled-wire-label0 in2))
                            (logior (ash gate-id 1) 1)))
         (h-b1 (hash-to-key (wire-label-value (garbled-wire-label1 in2))
                            (logior (ash gate-id 1) 1)))
         ;; Garbler half-gate
         (tg (if (zerop pa)
                 (xor-bytes h-a0 h-a1)
                 (xor-bytes h-a0 (xor-bytes h-a1
                                             (wire-label-value global-offset)))))
         ;; Evaluator half-gate
         (te (if (zerop pb)
                 (xor-bytes h-b0 (xor-bytes h-b1
                                             (wire-label-value (garbled-wire-label0 in1))))
                 (xor-bytes h-b0 (xor-bytes h-b1
                                             (wire-label-value (garbled-wire-label1 in1)))))))
    ;; Set output wire labels
    (setf (garbled-wire-label0 out)
          (make-wire-label :value h-a0 :pointer-bit 0))
    (setf (garbled-wire-label1 out)
          (wire-label-xor (garbled-wire-label0 out) global-offset))
    ;; Return two-row table
    (list (cons 0 tg) (cons 1 te))))

;;; ============================================================================
;;; Row Reduction Optimization
;;; ============================================================================

(defun garble-gate-row-reduction (gate-type in1 in2 out gate-id)
  "Garble gate with row reduction (3 rows instead of 4)."
  (let* ((truth-table (case gate-type
                        (:and '((0 0 0) (0 1 0) (1 0 0) (1 1 1)))
                        (:or  '((0 0 0) (0 1 1) (1 0 1) (1 1 1)))))
         (table '()))
    ;; Process each row
    (dolist (row truth-table)
      (let* ((a (first row))
             (b (second row))
             (c (third row))
             (key1 (if (zerop a)
                       (garbled-wire-label0 in1)
                       (garbled-wire-label1 in1)))
             (key2 (if (zerop b)
                       (garbled-wire-label0 in2)
                       (garbled-wire-label1 in2)))
             (row-idx (logior (ash (wire-label-pointer-bit key1) 1)
                              (wire-label-pointer-bit key2))))
        (if (zerop row-idx)
            ;; First row: derive output label from hash
            (let* ((derived (hash-to-key
                             (xor-bytes (wire-label-value key1)
                                        (wire-label-value key2))
                             gate-id))
                   (label (make-wire-label :value derived :pointer-bit c)))
              (if (zerop c)
                  (setf (garbled-wire-label0 out) label)
                  (setf (garbled-wire-label1 out) label)))
            ;; Other rows: encrypt normally
            (let ((plaintext (if (zerop c)
                                 (or (garbled-wire-label0 out)
                                     (make-wire-label
                                      :value (get-random-bytes 16)
                                      :pointer-bit 0))
                                 (or (garbled-wire-label1 out)
                                     (make-wire-label
                                      :value (get-random-bytes 16)
                                      :pointer-bit 1)))))
              (when (zerop c)
                (setf (garbled-wire-label0 out) plaintext))
              (when (not (zerop c))
                (setf (garbled-wire-label1 out) plaintext))
              (push (cons row-idx
                          (garble-encrypt key1 key2 gate-id row-idx plaintext))
                    table)))))
    (nreverse table)))

;;; ============================================================================
;;; Circuit Garbling
;;; ============================================================================

(defun garble-circuit (circuit-spec &key (optimization :half-gates))
  "Garble a circuit specification.
CIRCUIT-SPEC format: (:inputs (id ...) :outputs (id ...) :gates ((type in1 in2 out) ...))
OPTIMIZATION: :standard, :free-xor, :half-gates, or :row-reduction"
  (let* ((inputs (getf circuit-spec :inputs))
         (outputs (getf circuit-spec :outputs))
         (gates (getf circuit-spec :gates))
         (wire-labels (make-hash-table))
         (global-offset (when (member optimization '(:free-xor :half-gates))
                          (generate-global-offset)))
         (garbled-gates '())
         (gate-id 0))
    ;; Generate input wire labels
    (dolist (wire-id inputs)
      (setf (gethash wire-id wire-labels)
            (generate-wire-labels wire-id global-offset)))
    ;; Process gates in topological order
    (dolist (gate-spec gates)
      (let* ((gate-type (first gate-spec))
             (in1-id (second gate-spec))
             (in2-id (third gate-spec))
             (out-id (fourth gate-spec))
             (in1 (gethash in1-id wire-labels))
             (in2 (when in2-id (gethash in2-id wire-labels)))
             (out (generate-wire-labels out-id global-offset))
             (table nil))
        (setf (gethash out-id wire-labels) out)
        ;; Garble based on gate type and optimization
        (setf table
              (cond
                ;; NOT gate (single input)
                ((eq gate-type :not)
                 (setf (garbled-wire-label0 out) (garbled-wire-label1 in1))
                 (setf (garbled-wire-label1 out) (garbled-wire-label0 in1))
                 nil)
                ;; XOR with Free XOR optimization
                ((and (eq gate-type :xor) global-offset)
                 (garble-xor-gate in1 in2 out global-offset))
                ;; AND with Half-Gates
                ((and (eq gate-type :and) (eq optimization :half-gates))
                 (garble-and-gate-half-gates in1 in2 out gate-id global-offset))
                ;; Row reduction
                ((eq optimization :row-reduction)
                 (garble-gate-row-reduction gate-type in1 in2 out gate-id))
                ;; Standard
                (t (garble-gate-standard gate-type in1 in2 out gate-id))))
        (push (make-garbled-gate
               :id gate-id
               :type gate-type
               :input-wires (if in2-id (list in1-id in2-id) (list in1-id))
               :output-wire out-id
               :table table)
              garbled-gates)
        (incf gate-id)))
    ;; Build decoding info for outputs
    (let ((decoding (loop for out-id in outputs
                          collect (cons out-id
                                        (wire-label-pointer-bit
                                         (garbled-wire-label0
                                          (gethash out-id wire-labels)))))))
      (make-garbled-circuit
       :gates (nreverse garbled-gates)
       :input-wires inputs
       :output-wires outputs
       :wire-labels wire-labels
       :global-offset global-offset
       :decoding-info decoding))))

;;; ============================================================================
;;; Circuit Evaluation
;;; ============================================================================

(defun evaluate-garbled-gate (gate input-labels)
  "Evaluate a garbled gate given input labels."
  (let* ((table (garbled-gate-table gate))
         (in1 (first input-labels))
         (in2 (second input-labels))
         (gate-id (garbled-gate-id gate)))
    (cond
      ;; Free XOR gate (empty table)
      ((and (eq (garbled-gate-type gate) :xor) (null table))
       (wire-label-xor in1 in2))
      ;; NOT gate
      ((eq (garbled-gate-type gate) :not)
       in1)  ; Labels are swapped during garbling
      ;; Half-gates AND
      ((and (eq (garbled-gate-type gate) :and)
            (= (length table) 2))
       (let* ((tg (cdr (first table)))
              (te (cdr (second table)))
              (sa (wire-label-pointer-bit in1))
              (sb (wire-label-pointer-bit in2))
              ;; Garbler half-gate
              (h-a (hash-to-key (wire-label-value in1)
                                (logior (ash gate-id 1) 0)))
              (wg (if (zerop sa)
                      h-a
                      (xor-bytes h-a tg)))
              ;; Evaluator half-gate
              (h-b (hash-to-key (wire-label-value in2)
                                (logior (ash gate-id 1) 1)))
              (we (if (zerop sb)
                      h-b
                      (xor-bytes h-b (xor-bytes te (wire-label-value in1))))))
         (make-wire-label :value (xor-bytes wg we)
                          :pointer-bit (logand 1
                                               (logxor (logand sa sb)
                                                       (aref wg 15)
                                                       (aref we 15))))))
      ;; Standard or row-reduced
      (t
       (let* ((row-idx (logior (ash (wire-label-pointer-bit in1) 1)
                               (wire-label-pointer-bit in2)))
              (entry (assoc row-idx table)))
         (if entry
             ;; Decrypt from table
             (let ((decrypted (garble-decrypt in1 in2 gate-id row-idx (cdr entry))))
               (make-wire-label :value decrypted
                                :pointer-bit (logand (aref decrypted 15) 1)))
             ;; Row reduction: derive from hash
             (let ((derived (hash-to-key
                             (xor-bytes (wire-label-value in1)
                                        (wire-label-value in2))
                             gate-id)))
               (make-wire-label :value derived
                                :pointer-bit (logand (aref derived 15) 1)))))))))

(defun evaluate-garbled-circuit (circuit input-labels)
  "Evaluate a garbled circuit with given input labels.
INPUT-LABELS: list of wire-label for each input wire."
  (let ((wire-values (make-hash-table)))
    ;; Set input wire values
    (loop for wire-id in (garbled-circuit-input-wires circuit)
          for label in input-labels
          do (setf (gethash wire-id wire-values) label))
    ;; Evaluate gates in order
    (dolist (gate (garbled-circuit-gates circuit))
      (let* ((input-ids (garbled-gate-input-wires gate))
             (inputs (mapcar (lambda (id) (gethash id wire-values)) input-ids))
             (output-id (garbled-gate-output-wire gate))
             (output-label (evaluate-garbled-gate gate inputs)))
        (setf (gethash output-id wire-values) output-label)))
    ;; Return output wire labels
    (mapcar (lambda (id) (gethash id wire-values))
            (garbled-circuit-output-wires circuit))))

;;; ============================================================================
;;; Input Encoding / Output Decoding
;;; ============================================================================

(defun encode-input (circuit input-bits)
  "Encode input bits to wire labels for circuit evaluation."
  (let ((wire-labels (garbled-circuit-wire-labels circuit)))
    (loop for wire-id in (garbled-circuit-input-wires circuit)
          for bit in input-bits
          collect (let ((wire (gethash wire-id wire-labels)))
                    (if (zerop bit)
                        (garbled-wire-label0 wire)
                        (garbled-wire-label1 wire))))))

(defun decode-output (circuit output-labels)
  "Decode output wire labels to bits."
  (let ((decoding (garbled-circuit-decoding-info circuit)))
    (loop for label in output-labels
          for (wire-id . expected-pointer-for-0) in decoding
          collect (if (= (wire-label-pointer-bit label) expected-pointer-for-0)
                      0
                      1))))

;;; ============================================================================
;;; 2PC Protocol
;;; ============================================================================

(defun gc-2pc-garble (circuit-spec garbler-input)
  "Garbler side of 2PC: garble circuit and encode own input.
Returns (values garbled-circuit encoded-garbler-input evaluator-input-labels)."
  (let* ((gc (garble-circuit circuit-spec))
         (num-garbler-inputs (length garbler-input))
         (all-inputs (garbled-circuit-input-wires gc))
         (garbler-wires (subseq all-inputs 0 num-garbler-inputs))
         (evaluator-wires (subseq all-inputs num-garbler-inputs))
         (wire-labels (garbled-circuit-wire-labels gc))
         ;; Encode garbler's input
         (garbler-labels (loop for wire-id in garbler-wires
                               for bit in garbler-input
                               collect (let ((wire (gethash wire-id wire-labels)))
                                         (if (zerop bit)
                                             (garbled-wire-label0 wire)
                                             (garbled-wire-label1 wire)))))
         ;; Prepare evaluator's input labels (both options for OT)
         (evaluator-label-pairs
           (loop for wire-id in evaluator-wires
                 collect (let ((wire (gethash wire-id wire-labels)))
                           (cons (garbled-wire-label0 wire)
                                 (garbled-wire-label1 wire))))))
    (values gc garbler-labels evaluator-label-pairs)))

(defun gc-2pc-evaluate (gc garbler-labels evaluator-labels)
  "Evaluator side of 2PC: evaluate garbled circuit.
Returns output bits."
  (let* ((all-labels (append garbler-labels evaluator-labels))
         (output-labels (evaluate-garbled-circuit gc all-labels)))
    (decode-output gc output-labels)))

(defun gc-2pc-run (circuit-spec garbler-input evaluator-input)
  "Run complete 2PC protocol (for testing without OT).
In real protocol, evaluator-input would be obtained via OT."
  (multiple-value-bind (gc garbler-labels evaluator-label-pairs)
      (gc-2pc-garble circuit-spec garbler-input)
    (let ((evaluator-labels
            (loop for bit in evaluator-input
                  for pair in evaluator-label-pairs
                  collect (if (zerop bit) (car pair) (cdr pair)))))
      (gc-2pc-evaluate gc garbler-labels evaluator-labels))))

;;; ============================================================================
;;; Example Circuits
;;; ============================================================================

(defun make-and-circuit ()
  "Single AND gate circuit."
  '(:inputs (0 1) :outputs (2) :gates ((:and 0 1 2))))

(defun make-or-circuit ()
  "Single OR gate circuit."
  '(:inputs (0 1) :outputs (2) :gates ((:or 0 1 2))))

(defun make-xor-circuit ()
  "Single XOR gate circuit."
  '(:inputs (0 1) :outputs (2) :gates ((:xor 0 1 2))))

(defun make-not-circuit ()
  "Single NOT gate circuit."
  '(:inputs (0) :outputs (1) :gates ((:not 0 nil 1))))

(defun make-equality-circuit (bits)
  "Circuit to check if two BITS-bit numbers are equal."
  (let ((inputs (loop for i from 0 below (* 2 bits) collect i))
        (gates '())
        (next-wire (* 2 bits))
        (xor-outputs '()))
    ;; XOR corresponding bits
    (dotimes (i bits)
      (push (list :xor i (+ i bits) next-wire) gates)
      (push next-wire xor-outputs)
      (incf next-wire))
    ;; NOR tree to check all XORs are 0
    (let ((current-layer (nreverse xor-outputs)))
      (loop while (> (length current-layer) 1)
            do (let ((new-layer '()))
                 (loop while (>= (length current-layer) 2)
                       do (let ((a (pop current-layer))
                                (b (pop current-layer)))
                            (push (list :nor a b next-wire) gates)
                            (push next-wire new-layer)
                            (incf next-wire)))
                 (when current-layer
                   (push (car current-layer) new-layer))
                 (setf current-layer (nreverse new-layer))))
      (list :inputs inputs
            :outputs (list (car current-layer))
            :gates (nreverse gates)))))

(defun make-millionaires-circuit (bits)
  "Circuit for millionaire's problem: output 1 if A > B."
  ;; Simple comparison: start from MSB, propagate 'greater' flag
  (let ((inputs (loop for i from 0 below (* 2 bits) collect i))
        (gates '())
        (next-wire (* 2 bits))
        ;; Start with "neither greater"
        (gt-flag nil))
    (loop for i from (1- bits) downto 0
          for a-bit = i
          for b-bit = (+ i bits)
          do (let ((a-and-not-b next-wire)
                   (b-and-not-a (1+ next-wire))
                   (not-a (+ next-wire 2))
                   (not-b (+ next-wire 3)))
               ;; NOT a and NOT b
               (push (list :not a-bit nil not-a) gates)
               (push (list :not b-bit nil not-b) gates)
               ;; a AND (NOT b) - a > b for this bit
               (push (list :and a-bit not-b a-and-not-b) gates)
               ;; (NOT a) AND b - b > a for this bit
               (push (list :and not-a b-bit b-and-not-a) gates)
               (incf next-wire 4)
               ;; Propagate result
               (if gt-flag
                   (let ((eq-bit next-wire))
                     ;; Equal at this bit: XNOR
                     (push (list :xor a-bit b-bit eq-bit) gates)
                     (push (list :not eq-bit nil (1+ eq-bit)) gates)
                     (incf next-wire 2)
                     ;; New gt = old_gt AND eq OR a_and_not_b
                     (let ((gt-and-eq next-wire))
                       (push (list :and gt-flag (- next-wire 1) gt-and-eq) gates)
                       (incf next-wire)
                       (push (list :or gt-and-eq a-and-not-b next-wire) gates)
                       (setf gt-flag next-wire)
                       (incf next-wire)))
                   (setf gt-flag a-and-not-b))))
    (list :inputs inputs
          :outputs (list gt-flag)
          :gates (nreverse gates))))

(defun make-adder-circuit (bits)
  "Circuit for adding two BITS-bit numbers. Output is (BITS+1) bits."
  (let ((inputs (loop for i from 0 below (* 2 bits) collect i))
        (gates '())
        (next-wire (* 2 bits))
        (outputs '())
        (carry nil))
    (dotimes (i bits)
      (let ((a i)
            (b (+ i bits)))
        (if (null carry)
            ;; First bit: half adder
            (let ((sum next-wire)
                  (new-carry (1+ next-wire)))
              (push (list :xor a b sum) gates)
              (push (list :and a b new-carry) gates)
              (push sum outputs)
              (setf carry new-carry)
              (incf next-wire 2))
            ;; Full adder
            (let ((xor-ab next-wire)
                  (sum (1+ next-wire))
                  (and-ab (+ next-wire 2))
                  (and-xor-c (+ next-wire 3))
                  (new-carry (+ next-wire 4)))
              (push (list :xor a b xor-ab) gates)
              (push (list :xor xor-ab carry sum) gates)
              (push (list :and a b and-ab) gates)
              (push (list :and xor-ab carry and-xor-c) gates)
              (push (list :or and-ab and-xor-c new-carry) gates)
              (push sum outputs)
              (setf carry new-carry)
              (incf next-wire 5)))))
    ;; Final carry is MSB of result
    (push carry outputs)
    (list :inputs inputs
          :outputs (nreverse outputs)
          :gates (nreverse gates))))

(defun make-comparator-circuit (bits)
  "Circuit comparing two BITS-bit numbers. Outputs (equal, greater, less)."
  (let ((eq-circuit (make-equality-circuit bits))
        (gt-circuit (make-millionaires-circuit bits)))
    ;; Combine circuits (simplified - in practice would merge wire IDs)
    (list :description "Use make-equality-circuit and make-millionaires-circuit separately"
          :equal eq-circuit
          :greater gt-circuit)))
