use ethereum_tx_sign::{LegacyTransaction, Transaction};

use ethers::{
    core::types::TransactionRequest,
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    utils::{parse_ether, public_key_to_address},
};
use eyre::Result;
use frost_secp256k1 as frost;
use frost_secp256k1::serde::Serialize;
use frost_secp256k1::Signature;
use k256::ecdsa::VerifyingKey;
use rand::thread_rng;
use rlp::{Encodable, RlpStream};
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<(), frost::Error> {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let pubkey = pubkey_package.verifying_key();
    let pubkey_bytes = pubkey.serialize();
    let k256_pubkey = VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("valid key bytes");
    let address = public_key_to_address(&k256_pubkey);

    println!("rng: {:?}", rng);
    println!("shares: {:?}", shares);
    println!("pubkey_pages: {:?}", pubkey_package);
    println!("Ethereum address: {:?}", address);

    let _ = send_to_test_ether(address).await;
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

    let to_address: H160 = "0x6fC21092DA55B392b045eD78F4732bff3C580e2c"
        .parse()
        .expect("valid address");
    let value = parse_ether(1u64).expect("msg");
    println!("value: {:?}", value);

    // it knows to figure out the default gas value and determine the next nonce so no need to explicitly add them unless you want to
    let tx = TransactionRequest::new().to(to_address).value(value);
    let tx_rlp_unsigned = tx.rlp_unsigned();
    let tx_rlp_as_ref = tx_rlp_unsigned.as_ref();
    println!("tx_rlp_as_ref: {:?}", tx_rlp_as_ref);

    // In practice, the SigningPackage must be sent to all participants
    // involved in the current signing (at least min_signers participants),
    // using an authenticate channel (and confidential if the message is secret).
    let signing_package = frost::SigningPackage::new(commitments_map, tx_rlp_as_ref);
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
        .verify(tx_rlp_as_ref, &group_signature)
        .is_ok();
    // ANCHOR_END: verify
    println!("{:?}", is_signature_valid);

    Ok(())
}

async fn send_to_test_ether(to_address: Address) -> Result<()> {
    let provider = Provider::<Http>::try_from(
        "https://sepolia.infura.io/v3/6a374a6162be4f7cabf041885f15d3b1",
    )?;

    let chain_id = provider.get_chainid().await?;

    let wallet: LocalWallet = "aa2694dd8edaa44893fbd0d0f3110d821fb071ccd9e6d434aee58078cf83caa5"
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id.as_u64());
    println!("{:?}", wallet);
    // connect the wallet to the provider
    let client = SignerMiddleware::new(provider, wallet);

    // Craft the transaction
    // The below code knows how to figure out the
    // default gas value and determine the next nonce
    // so you do not need to explicitly add them.
    let tx = TransactionRequest::new()
        .to(to_address)
        .value(U256::from(parse_ether(0.001)?));

    let pending_tx = client.send_transaction(tx, None).await?;
    let receipt = pending_tx
        .await?
        .ok_or_else(|| eyre::format_err!("tx dropped from mempool"))?;
    let tx = client.get_transaction(receipt.transaction_hash).await?;
    println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
    println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

    Ok(())
}
