use bicycl_rs::Context;

fn main() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("1").unwrap();
    let session = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    // Should fail: New state has no prove_round method
    let _ = session.prove_round(&ctx, &mut rng);
}
