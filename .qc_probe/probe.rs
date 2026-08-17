use ed25519_dalek::{VerifyingKey, Signature, Verifier};
fn main() {
    // case A: identity-point encoding accepted by from_bytes?
    let mut ident = [0u8; 32]; ident[0] = 1;
    let a = VerifyingKey::from_bytes(&ident);
    println!("identity from_bytes ok: {}", a.is_ok());
    // case B: order-4 encoding (all zero bytes)
    let b = VerifyingKey::from_bytes(&[0u8; 32]);
    println!("order4 from_bytes ok: {}", b.is_ok());
    // case C: non-canonical field value (>= p) encoding
    let mut nc = [0xffu8; 32]; nc[0] = 0xee; nc[31] = 0x7f;
    let c = VerifyingKey::from_bytes(&nc);
    println!("noncanonical from_bytes ok: {}", c.is_ok());
    // case D: under identity key, does plain verify accept a crafted pair (R = S*B)?
    if let Ok(vk) = a {
        println!("identity is_weak: {}", vk.is_weak());
        let mut sig = [0u8; 64];
        // R := basepoint encoding, S := scalar one
        let base: [u8; 32] = [0x58,0x66
