use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
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

pub fn generate_utxo_hash(
    random: Vec<u8>,
    master_pubkey: Vec<u8>,
    token_id: Vec<u8>,
    amount: u64,
) -> Vec<u8> {
    let uxto_pubkey = sha256(vec![master_pubkey.as_slice(), random.as_slice()]);
    let value: Vec<u8> = amount.to_le_bytes().to_vec();

    sha256(vec![
        uxto_pubkey.as_slice(),
        token_id.as_slice(),
        value.as_slice(),
    ])
}

pub fn get_pubkey(key: Vec<u8>) -> Vec<u8> {
    let mut secret_key = [0u8; SECRET_KEY_LENGTH];
    secret_key.copy_from_slice(&key.clone());
    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
    signing_key.verifying_key().as_bytes().to_vec()
}
