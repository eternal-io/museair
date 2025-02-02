#[inline(never)]
pub fn hash_standard(bytes: &[u8], seed: u64) -> u64 {
    museair::hash(bytes, seed)
}

#[inline(never)]
pub fn hash_bfast(bytes: &[u8], seed: u64) -> u64 {
    museair::bfast::hash(bytes, seed)
}

#[inline(never)]
pub fn rapidhash(bytes: &[u8], seed: u64) -> u64 {
    rapidhash::rapidhash_inline(bytes, seed)
}
