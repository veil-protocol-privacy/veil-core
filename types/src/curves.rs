use sha2::{Digest, Sha512};
use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};

pub fn blind_keys(
    sender_viewing_pubkey: Vec<u8>,
    receiver_viewing_pubkey: Vec<u8>,
    random: Vec<u8>,
)-> (Vec<u8>, Vec<u8>) {
    let blinding_scalar = Scalar::hash_from_bytes::<Sha512>(&random);
    let sender_pubkey_compressed = CompressedEdwardsY::from_slice(&sender_viewing_pubkey).unwrap();
    let sender_pubkey_point = sender_pubkey_compressed.decompress().unwrap();

    let receiver_pubkey_compressed = CompressedEdwardsY::from_slice(&receiver_viewing_pubkey).unwrap();
    let receiver_pubkey_point = receiver_pubkey_compressed.decompress().unwrap();

    let blinded_sender_pubkey_point = sender_pubkey_point * blinding_scalar;
    let blinded_receiver_pubkey_point = receiver_pubkey_point * blinding_scalar;
    
    let blinded_sender_pubkey = blinded_sender_pubkey_point.compress().as_bytes().to_vec();
    let blinded_receiver_pubkey = blinded_receiver_pubkey_point.compress().as_bytes().to_vec();
    (blinded_sender_pubkey, blinded_receiver_pubkey)
}

pub fn share_key(
    private_key: Vec<u8>,
    public_key: Vec<u8>,
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    Digest::update(&mut hasher, private_key.as_slice());
    let private_hash = hasher.finalize();

    // takes only 32 bytes of the hash, put in le
    let mut head = [0; 32];
    head.copy_from_slice(&private_hash.as_slice()[..32]);
    head[0] &= 0b11111000;
    head[31] &= 0b01111111;
    head[31] |= 0b01000000;
    
    let private_key_scalar = Scalar::from_bytes_mod_order(head);

    let public_key_compressed = CompressedEdwardsY::from_slice(&public_key).unwrap();
    let public_key_point = public_key_compressed.decompress().unwrap();

    (public_key_point * private_key_scalar).compress().as_bytes().to_vec()
}
