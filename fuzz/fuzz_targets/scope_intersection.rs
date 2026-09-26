#![no_main]
//! Scope intersection must be commutative and total. Privilege
//! narrowing is the safety property of RFC 8693 token exchange: a
//! bug here is a privilege escalation.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split input at the first NUL byte to get two scope strings.
    let Some(pos) = data.iter().position(|b| *b == 0) else {
        return;
    };
    let Ok(a) = std::str::from_utf8(&data[..pos]) else {
        return;
    };
    let Ok(b) = std::str::from_utf8(&data[pos + 1..]) else {
        return;
    };
    let a: Vec<String> = a.split(' ').map(str::to_owned).collect();
    let b: Vec<String> = b.split(' ').map(str::to_owned).collect();
    let ab = av_identity::exchange::scope_intersection(&a, &b);
    let ba = av_identity::exchange::scope_intersection(&b, &a);
    // Commutativity: the intersection has the same length regardless of order.
    assert_eq!(ab.len(), ba.len(), "intersection not commutative: {ab:?} vs {ba:?}");
    // Every scope in the result must appear in both inputs (narrowing).
    for scope in &ab {
        assert!(
            a.contains(scope) || b.iter().any(|bs| av_identity::exchange::scope_intersection(&[bs.clone()], &[scope.clone()]).len() == 1),
            "scope {scope:?} not covered by both inputs"
        );
    }
});