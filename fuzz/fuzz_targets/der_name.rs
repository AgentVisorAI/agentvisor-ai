#![no_main]
//! The hand-rolled DER reader behind Cloud Foundry instance identity must
//! be total: a malformed or hostile `x5c` subject name must produce `None`
//! or an error, never a panic and never a slice that runs past the input.
//! A panic here is a denial of service on every workload assertion.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The TLV splitter must never panic and must never hand back a value
    // or rest slice larger than what it was given.
    if let Some((_tag, value, rest)) = av_identity::workload::tlv(data) {
        assert!(
            value.len() + rest.len() <= data.len(),
            "TLV slices escaped the input: value {} + rest {} > input {}",
            value.len(),
            rest.len(),
            data.len()
        );
        let header = data.len() - value.len() - rest.len();
        assert!(header >= 2, "TLV header shorter than a tag and a length");
    }

    // The name parser must be total as well.
    let _ = av_identity::workload::name_attributes(data);

    // And so must the identity reader, which layers policy on top.
    let _ = av_identity::workload::cf_identity(data);
});