use bicycl_rs::Context;

fn main() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("1").unwrap();
    let session = ctx.two_party_ecdsa_session(&mut rng, 112).unwrap();
    // Should fail: New state has no sign_round1 method
    let _ = session.sign_round1(&ctx, &mut rng, b"msg");
}
