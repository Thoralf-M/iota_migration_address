use wasm_bindgen::prelude::*;

use bee_message::prelude::{Address, Ed25519Address};
use bee_ternary::{b1t6, T1B1Buf, T3B1Buf, Trits, TryteBuf};
use bee_transaction::bundled::{Address as TryteAddress, BundledTransactionField};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use crypto::hashes::ternary::kerl::Kerl;
use crypto::hashes::ternary::Sponge;

use core::convert::TryInto;
extern crate console_error_panic_hook;
use std::panic;
use wasm_bindgen::JsValue;

/// Convert errors so they are readable in JS
pub fn err<T>(error: T) -> JsValue
where
    T: ToString,
{
    error.to_string().into()
}

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    Ok(())
}

#[wasm_bindgen]
pub fn convert_to_tryte_address(address: &str) -> Result<String, JsValue> {
    let address = Address::try_from_bech32(&address).map_err(err)?;
    let ed25519_address = match address {
        Address::Ed25519(a) => a,
        _ => panic!("Unsupported address type"),
    };
    let migration_address = encode_migration_address(ed25519_address)?;
    let migration_address = add_tryte_checksum(migration_address)?;
    Ok(migration_address)
}

#[wasm_bindgen]
pub fn convert_to_migration_address(address: &str) -> Result<String, JsValue> {
    let tryte_address = TryteAddress::from_inner_unchecked(
        TryteBuf::try_from_str(address).unwrap().as_trits().encode(),
    );
    Ok(Address::Ed25519(decode_migration_address(tryte_address)?).to_bech32("iota"))
}

/// Encode an Ed25519Address to a TryteAddress
// https://hackmd.io/@iota-protocol/rkO-r1qAv#Generating-the-81-tryte-migration-address
pub fn encode_migration_address(ed25519_address: Ed25519Address) -> Result<TryteAddress, JsValue> {
    // Compute the BLAKE2b-256 hash H of A.
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.update(ed25519_address);
    let mut result: Option<[u8; 32]> = None;
    hasher.finalize_variable(|res| {
        result = res.try_into().ok();
    });
    let result: [u8; 32] = result.unwrap();
    // Append the first 4 bytes of H to A, resulting in 36 bytes.
    let trytes = b1t6::encode::<T1B1Buf>(&[ed25519_address.as_ref(), &result[0..4]].concat())
        .iter_trytes()
        .map(char::from)
        .collect::<String>();
    // Prepend TRANSFER and pad with 9 to get 81 Trytes
    let transfer_address = format!("TRANSFER{}9", trytes);
    Ok(TryteAddress::from_inner_unchecked(
        TryteBuf::try_from_str(&transfer_address)
            .map_err(err)?
            .as_trits()
            .encode(),
    ))
}

/// Decode a TryteAddress to an Ed25519Address
// https://hackmd.io/@iota-protocol/rkO-r1qAv#Decoding-the-81-tryte-migration-address
pub fn decode_migration_address(tryte_address: TryteAddress) -> Result<Ed25519Address, JsValue> {
    let tryte_string = tryte_address
        .to_inner()
        .encode::<T3B1Buf>()
        .iter_trytes()
        .map(char::from)
        .collect::<String>();
    if &tryte_string[0..8] != "TRANSFER" {
        return Err("Invalid address, doesn't start with 'TRANSFER'".into());
    }
    if &tryte_string[80..81] != "9" {
        return Err("Invalid address, doesn't end with '9'".into());
    }

    let ed25519_address_bytes = b1t6::decode(&tryte_address.to_inner().subslice(24..240)).unwrap();

    //The first 32 bytes of the result are called A and the last 4 bytes H.
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.update(&ed25519_address_bytes[0..32]);
    let mut result: Option<[u8; 32]> = None;
    hasher.finalize_variable(|res| {
        result = res.try_into().ok();
    });
    let result: [u8; 32] = result.unwrap();
    //Check that H matches the first 4 bytes of the BLAKE2b-256 hash of A.
    if ed25519_address_bytes[32..36] != result[0..4] {
        return Err("Blake2b hash of the Ed25519Address doesn't match".into());
    }

    Ok(Ed25519Address::new(
        ed25519_address_bytes[0..32].try_into().unwrap(),
    ))
}

/// Add 9 Trytes checksum to an address and return it as String
pub fn add_tryte_checksum(address: TryteAddress) -> Result<String, JsValue> {
    let mut kerl = Kerl::new();
    let hash = kerl
        .digest(
            Trits::try_from_raw(
                &[address.to_inner().as_i8_slice(), &[0, 0, 0]].concat(),
                243,
            )
            .unwrap(),
        )
        .unwrap()
        .iter_trytes()
        .map(char::from)
        .collect::<String>();

    Ok(format!(
        "{}{}",
        address
            .to_inner()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>(),
        &hash[72..81]
    ))
}
