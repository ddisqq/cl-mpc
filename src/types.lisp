;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-mpc)

;;; Core types for cl-mpc
(deftype cl-mpc-id () '(unsigned-byte 64))
(deftype cl-mpc-status () '(member :ready :active :error :shutdown))
