use acme_ec::constants::BASE_TABLE;

fn table() {
    let t = BASE_TABLE;
    let q = &BASE_TABLE * 2;
    let r = acme_ec::constants::BASE_TABLE;
    let _ = (t, q, r);
}

mod other {
    use acme_ec::constants;
    fn module() {
        let m = constants::BASE_TABLE;
        let n = crate::constants::BASE_TABLE;
        let _ = (m, n);
    }
}
