(module
  (memory (export "memory") 256)
  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 0))
  (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
    (if (result i32)
      (i32.gt_u (local.get $len) (i32.const 1048576))
      (then (i32.const 1))
      (else (i32.const 0)))))
