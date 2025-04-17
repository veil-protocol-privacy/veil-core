use borsh::{BorshDeserialize, BorshSerialize};

pub mod curves;
pub mod utils;
pub mod utxo;

pub use curves::*;
pub use utils::*;
pub use utxo::*;

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct Arguments {
    pub public_data: PublicData,
    pub private_data: PrivateData,
    pub tree_depth: u64,
    pub input_count: u64,
    pub output_count: u64,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct PublicData {
    pub merkle_root: Vec<u8>,
    pub params_hash: Vec<u8>,
    pub nullifiers: Vec<Vec<u8>>,
    pub output_hashes: Vec<Vec<u8>>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct PrivateData {
    pub token_id: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub random_inputs: Vec<Vec<u8>>,
    pub amount_in: Vec<u64>,
    pub merkle_paths: Vec<Vec<Vec<u8>>>,
    pub merkle_leaf_indices: Vec<u64>,
    pub nullifying_key: Vec<u8>,
    pub utxo_output_keys: Vec<Vec<u8>>,
    pub amount_out: Vec<u64>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct CommitmentPlainText {
    pub master_pubkey: Vec<u8>,
    pub random: Vec<u8>,
    pub amount: u64,
    pub token_id: Vec<u8>,
    pub memo: String,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct DepositPlainText {
    pub encrypted_random: Vec<u8>,
    pub encrypted_receiver: Vec<u8>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct CipherText {
    pub cipher: Vec<u8>,
    pub nonce: Vec<u8>,
    pub blinded_sender_pubkey: Vec<u8>,
    pub blinded_receiver_pubkey: Vec<u8>,
}

impl CipherText {
    pub fn new(
        cipher: Vec<u8>,
        nonce: Vec<u8>,
        blinded_sender_pubkey: Vec<u8>,
        blinded_receiver_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            cipher,
            nonce,
            blinded_sender_pubkey,
            blinded_receiver_pubkey,
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct DepositCiphertext {
    pub cipher: Vec<u8>,
    pub nonce: Vec<u8>,
    pub shield_key: Vec<u8>,
}

impl DepositCiphertext {
    pub fn new(cipher: Vec<u8>, nonce: Vec<u8>, shield_key: Vec<u8>) -> Self {
        Self { cipher, nonce, shield_key }
    }
}
