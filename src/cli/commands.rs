use crate::cli::args::GenArgs;

impl GenArgs {
    pub fn generate_password(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
        let password_len: usize = self.length;
        let mut rng = rand::thread_rng();

        let password: String = (0..password_len)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        password
    }
}
