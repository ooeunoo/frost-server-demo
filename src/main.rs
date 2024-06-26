use ethers::utils::public_key_to_address;
use frost_secp256k1 as frost;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::EncodedPoint;
use rand::thread_rng;
use std::collections::BTreeMap;

fn main() -> Result<(), frost::Error> {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;
    // ANCHOR_END: tkg_gen

    let pubkey = pubkey_package.verifying_key();
    println!("{:?}", pubkey);

    // Serialize the pubkey from frost to bytes
    let pubkey_bytes = pubkey.serialize();
    // Create a k256 VerifyingKey from the serialized bytes
    let k256_pubkey = VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("valid key bytes");
    let address = public_key_to_address(&k256_pubkey);

    println!("Ethereum address: {:?}", address);
    println!("shares: {:?}", shares);

    // Verifies the secret shares from the dealer and store them in a BTreeMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        // ANCHOR: tkg_verify
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        // ANCHOR_END: tkg_verify
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        // ANCHOR: round1_commit
        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].signing_share(),
            &mut rng,
        );
        // ANCHOR_END: round1_commit
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    // ANCHOR: round2_package
    let message = "message to sign".as_bytes();
    // In practice, the SigningPackage must be sent to all participants
    // involved in the current signing (at least min_signers participants),
    // using an authenticate channel (and confidential if the message is secret).
    let signing_package = frost::SigningPackage::new(commitments_map, message);
    println!("Signing package: {:?}", signing_package);
    // ANCHOR_END: round2_package

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        // ANCHOR: round2_sign
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;
        // ANCHOR_END: round2_sign

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    // ANCHOR: aggregate
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    // ANCHOR_END: aggregate
    
    println!("pubkey_package: {:?}", pubkey_package);
    println!("group signature: {:?}", group_signature);
    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    // ANCHOR: verify
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    // ANCHOR_END: verify
    println!("{:?}", is_signature_valid);

    Ok(())
}
