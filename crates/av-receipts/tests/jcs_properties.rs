//! Randomized property tests for JCS canonicalization: totality and
//! idempotence over arbitrary JSON. The idempotence property caught the
//! integer-form-double round-trip gap fixed in `write_number` (a double in
//! (2^53, 10^21) canonicalized to integer digits whose re-parse the
//! integer path refused — sign-once, never re-verify).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use serde_json::Value;

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        "\\PC*".prop_map(Value::String),
    ];
    leaf.prop_recursive(6, 128, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map("\\PC*", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// canonicalize is total (never panics) and, when it succeeds, is
    /// idempotent: parsing the canonical text and canonicalizing again
    /// must produce byte-identical output.
    #[test]
    fn canonicalize_is_total_and_idempotent(value in arb_json()) {
        if let Ok(first) = av_receipts::canonicalize(&value) {
            let reparsed: Value = serde_json::from_str(&first)
                .expect("canonical output must be valid JSON");
            let second = av_receipts::canonicalize(&reparsed)
                .expect("canonical output must re-canonicalize");
            prop_assert_eq!(&first, &second, "canonicalization must be idempotent");
        }
    }
}
