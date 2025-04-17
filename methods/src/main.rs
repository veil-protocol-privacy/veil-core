#![no_main]
sp1_zkvm::entrypoint!(main);

use borsh::BorshDeserialize;
use ed25519_dalek::{Signature, VerifyingKey};
use types::{
    utils::{hash_left_right, sha256},
    Arguments,
};

fn main() {
    let input = sp1_zkvm::io::read_vec();
    let args: Arguments = Arguments::deserialize(&mut input.as_slice()).unwrap();
    let input_count = args.input_count as usize;
    let output_count = args.output_count as usize;

    assert!(
        args.public_data.nullifiers.len() == input_count
            && args.public_data.output_hashes.len() == output_count
            && args.private_data.random_inputs.len() == input_count
            && args.private_data.amount_in.len() == input_count
            && args.private_data.merkle_paths.len() == input_count
            && args.private_data.merkle_leaf_indices.len() == input_count
            && args.private_data.utxo_output_keys.len() == output_count
            && args.private_data.amount_out.len() == output_count
    );

    let mut message_data: Vec<&[u8]> = vec![
        args.public_data.merkle_root.as_slice(),
        args.public_data.params_hash.as_slice(),
    ];
    message_data.extend(
        args.public_data
            .nullifiers
            .iter()
            .map(|nullifier| nullifier.as_slice()),
    );
    message_data.extend(
        args.public_data
            .output_hashes
            .iter()
            .map(|output_hash| output_hash.as_slice()),
    );

    let message_hash = sha256(message_data);
    let pubkey =
        VerifyingKey::from_bytes(&args.private_data.pubkey.as_slice().try_into().unwrap()).unwrap();
    let signature =
        Signature::from_bytes(&args.private_data.signature.as_slice().try_into().unwrap());

    let err = pubkey.verify_strict(&message_hash, &signature).err();
    if err.is_some() {
        panic!("{}", err.unwrap());
    };

    let nullifying_key = args.private_data.nullifying_key;
    let master_pubkey = sha256(vec![&args.private_data.pubkey, &nullifying_key]);

    args.public_data
        .nullifiers
        .iter()
        .enumerate()
        .for_each(|(i, nullifier)| {
            let leaf_index = args.private_data.merkle_leaf_indices[i].to_le_bytes();
            let nullifier_hash = sha256(vec![nullifying_key.as_slice(), &leaf_index]);
            assert!(nullifier.eq(&nullifier_hash));
        });

    let root = args.public_data.merkle_root;
    let token_id = args.private_data.token_id;

    for i in 0..input_count {
        let random = args.private_data.random_inputs.get(i).unwrap();
        let utxo_key_in = sha256(vec![&master_pubkey, random]);
        let amount_in = args.private_data.amount_in[i];
        assert!(amount_in != 0);

        let input_hash = sha256(vec![&utxo_key_in, &token_id, &amount_in.to_le_bytes()]);

        let leaf_index = args.private_data.merkle_leaf_indices[i];
        merkle_proof_check(
            input_hash,
            leaf_index,
            root.clone(),
            args.private_data.merkle_paths[i].clone(),
            args.tree_depth,
        );
    }

    args.public_data
        .output_hashes
        .iter()
        .enumerate()
        .for_each(|(i, output_hash)| {
            let amount_out = args.private_data.amount_out[i].to_le_bytes();
            let hash = sha256(vec![
                &args.private_data.utxo_output_keys[i],
                &token_id,
                &amount_out,
            ]);
            assert!(hash.eq(output_hash));
        });

    let sum_id = args.private_data.amount_in.iter().sum::<u64>();
    let sum_out = args.private_data.amount_out.iter().sum::<u64>();
    assert!(sum_id == sum_out);
}

fn merkle_proof_check(
    leaf: Vec<u8>,
    leaf_index: u64,
    root: Vec<u8>,
    path: Vec<Vec<u8>>,
    tree_depth: u64,
) {
    let mut current_hash = leaf;
    let mut index = leaf_index;

    assert!(path.len() == (tree_depth - 1) as usize);

    for sibling in path.iter() {
        let (left, right) = if index % 2 == 0 {
            (current_hash, sibling.clone())
        } else {
            (sibling.clone(), current_hash)
        };

        current_hash = hash_left_right(left, right);
        index /= 2;
    }

    assert_eq!(current_hash, root);
}
