# cl-mpc

Pure Common Lisp Multi-Party Computation library with **zero external dependencies**.

## Features

### Secret Sharing
- **Shamir Secret Sharing**: Split secrets into n shares with t-of-n threshold reconstruction
- **Feldman VSS**: Verifiable secret sharing with public commitments
- **Pedersen VSS**: Information-theoretically hiding verifiable secret sharing
- **Distributed Key Generation (DKG)**: Generate shared keys without a trusted dealer
- **Proactive Secret Sharing**: Refresh shares to limit adversary exposure time
- **Packed Secret Sharing**: Efficiently share multiple secrets

### Secure Computation
- **Additive Secret Sharing**: Simple share arithmetic
- **Beaver Triples**: Pre-computed multiplication triples
- **SPDZ Protocol**: Authenticated secret sharing with MAC verification

### Oblivious Transfer
- **1-of-2 OT**: Basic oblivious transfer
- **1-of-n OT**: Choose one of n messages
- **Base OT**: Chou-Orlandi style
- **OT Extension**: Extend base OTs efficiently (IKNP-style)
- **Random OT**: Transfer random values
- **Correlated OT**: Transfer correlated values
- **Batched OT**: Multiple OTs in parallel

### Garbled Circuits
- **Yao's Protocol**: Basic garbled circuit construction
- **Free XOR**: XOR gates with no garbled table
- **Half-Gates**: AND gates with 2 ciphertexts instead of 4
- **Row Reduction**: 3-row tables instead of 4
- **2PC Protocol**: Two-party secure computation

### Example Circuits
- AND, OR, XOR, NOT gates
- Equality comparison
- Millionaire's problem (greater-than)
- Binary addition
- General comparator

## Requirements

- SBCL (Steel Bank Common Lisp)
- No external dependencies

## Installation

```lisp
;; Clone the repository
;; cd cl-mpc

;; Load with ASDF
(asdf:load-system :cl-mpc)
```

## Quick Start

### Shamir Secret Sharing

```lisp
(use-package :cl-mpc)

;; Split a secret into 5 shares, requiring 3 to reconstruct
(let* ((secret 12345)
       (shares (split-secret secret 5 3)))
  ;; Reconstruct from any 3 shares
  (reconstruct-secret (subseq shares 0 3)))
;; => 12345
```

### Verifiable Secret Sharing (Feldman)

```lisp
;; Split with public verification
(multiple-value-bind (shares commitment)
    (feldman-vss-split 12345 5 3)
  ;; Anyone can verify a share against the commitment
  (feldman-vss-verify (first shares) commitment))
;; => T
```

### Secure Multiplication with Beaver Triples

```lisp
;; Generate Beaver triple shares
(let* ((triples (generate-beaver-triple 3 2))
       (x-shares (split-secret 7 3 2))
       (y-shares (split-secret 11 3 2)))
  ;; Multiply shares using Beaver protocol
  ;; (requires communication to open masked values)
  ...)
```

### Garbled Circuits

```lisp
;; Create and evaluate an AND circuit
(let* ((circuit (make-and-circuit))
       (result (gc-2pc-run circuit '(1) '(1))))
  result)
;; => (1)  ; 1 AND 1 = 1

;; Millionaire's problem (4-bit numbers)
(let* ((circuit (make-millionaires-circuit 4))
       (alice-wealth '(1 0 1 0))   ; 10 in binary
       (bob-wealth '(0 1 1 0)))    ; 6 in binary
  (gc-2pc-run circuit alice-wealth bob-wealth))
;; => (1)  ; Alice is richer
```

### Oblivious Transfer

```lisp
;; 1-of-2 OT: Receiver gets m0 or m1 without sender knowing which
(let* ((sender (ot-sender-init))
       (m0 #(1 2 3 4))
       (m1 #(5 6 7 8))
       (choice 1))  ; Receiver wants m1
  (multiple-value-bind (receiver-state blinded)
      (ot-receiver-choose (ot-sender-state-public-key sender) choice)
    (let ((ot-msg (ot-sender-transfer sender blinded m0 m1)))
      (ot-receiver-decrypt receiver-state
                           (ot-sender-state-public-key sender)
                           ot-msg))))
;; => #(5 6 7 8)  ; Receiver gets m1, sender doesn't know choice
```

### SPDZ Protocol

```lisp
;; Authenticated secret sharing with MAC
(multiple-value-bind (alpha mac-shares)
    (generate-mac-key-shares 3 2)
  (let ((shares (spdz-share-secret 42 alpha 3)))
    ;; Open with MAC verification
    (spdz-open-with-check shares mac-shares)))
;; => 42
```

## Architecture

```
cl-mpc/
  cl-mpc.asd          ; System definition
  package.lisp        ; Package exports
  src/
    util.lisp         ; Cryptographic primitives (SHA-256, AES, modular arithmetic)
    sharing.lisp      ; Secret sharing schemes (Shamir, VSS, DKG)
    garbled.lisp      ; Garbled circuits (Yao, Free XOR, Half-Gates)
    protocol.lisp     ; MPC protocols (OT, SPDZ)
```

## Security Notes

- This is a research/educational implementation
- Random number generation uses SBCL's `sb-ext:seed-random-state` on Windows, `/dev/urandom` on Unix
- The simplified OT uses Diffie-Hellman; production use should verify security assumptions
- MAC key generation should use proper key distribution in real deployments

## License

BSD-3-Clause. Copyright (c) 2024-2026 Parkian Company LLC.

## References

- Shamir, A. "How to Share a Secret" (1979)
- Feldman, P. "A Practical Scheme for Non-Interactive Verifiable Secret Sharing" (1987)
- Pedersen, T. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (1991)
- Yao, A. "How to Generate and Exchange Secrets" (1986)
- Kolesnikov, V. & Schneider, T. "Improved Garbled Circuit: Free XOR and Selective Security" (2008)
- Zahur, S., Rosulek, M. & Evans, D. "Two Halves Make a Whole" (2015)
- Damgard, I. et al. "Multiparty Computation from Somewhat Homomorphic Encryption" (SPDZ, 2012)
- Ishai, Y. et al. "Extending Oblivious Transfers Efficiently" (IKNP, 2003)
