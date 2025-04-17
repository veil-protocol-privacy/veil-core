use sha3::{Digest, Sha3_256};

pub fn sha256(inputs: Vec<&[u8]>) -> Vec<u8> {
    solana_sha256_hasher::hashv(&inputs).to_bytes().to_vec()
}

pub fn hash_left_right(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    solana_sha256_hasher::hashv(&[&left, &right])
        .to_bytes()
        .to_vec()
}

pub fn keccak(inputs: Vec<&[u8]>) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    for input in inputs {
        hasher.update(input);
    }

    let result = hasher.finalize();
    result.as_slice().to_vec()
}

pub fn generate_nullifier(viewing_key: Vec<u8>, leaf_index: u64) -> Vec<u8> {
    let nullifying_key = sha256(vec![viewing_key.as_slice()]);
    let leaf_index_bytes = leaf_index.to_le_bytes().to_vec();
    sha256(vec![nullifying_key.as_slice(), leaf_index_bytes.as_slice()])
}
