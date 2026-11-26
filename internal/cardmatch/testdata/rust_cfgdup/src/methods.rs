pub struct S;

impl S {
    #[cfg(unix)]
    fn run(&self) {
        acme::make(40);
    }

    #[cfg(not(unix))]
    fn run(&self) {
        acme::make(50);
    }
}
