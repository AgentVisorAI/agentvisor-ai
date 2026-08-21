;; Default payload-size policy.
;;
;; Round-6 (hunt5 config F1): the deny threshold matches the default
;; `max_request_bytes` (4 MiB) so the two request-size guards agree out
;; of the box. It was previously 1 MiB, which silently policy-blocked
;; chat requests between 1 and 4 MiB that the HTTP body limit had
;; admitted — misattributed as a policy violation in the audit trail.
;; If you raise `max_request_bytes` above 4 MiB, raise this constant
;; too (or remove this policy from `wasm_policy_paths`); the harness
;; warns at boot when the two disagree. Note the evaluation memory is
;; 16 MiB (256 pages) — payloads above ~16 MiB fail closed regardless.
(module
  (memory (export "memory") 256)
  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 0))
  (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
    (if (result i32)
      (i32.gt_u (local.get $len) (i32.const 4194304))
      (then (i32.const 1))
      (else (i32.const 0)))))
