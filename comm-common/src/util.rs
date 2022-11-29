use rand::{distributions::Alphanumeric, thread_rng, Rng};

/// Generate a random string for use as unique identification code
pub fn random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
