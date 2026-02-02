use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_crypto::{
    pedersen_hash as pedersen_hash_rs, poseidon_hash as poseidon_hash_rs,
    poseidon_hash_many as poseidon_hash_many_rs, poseidon_hash_single as poseidon_hash_single_rs,
    rfc6979_generate_k as rfc6979_generate_k_rs, sign as sign_rs, Felt,
};

fn biguint_to_felt(b: BigUint) -> Felt {
    Felt::from(b)
}

fn felt_to_biguint(f: Felt) -> BigUint {
    f.to_biguint()
}

#[pyfunction]
fn get_public_key(private_key: BigUint) -> PyResult<BigUint> {
    let pk = biguint_to_felt(private_key);
    Ok(felt_to_biguint(starknet_crypto::get_public_key(&pk)))
}

#[pyfunction]
fn pedersen_hash(left: BigUint, right: BigUint) -> PyResult<BigUint> {
    let left = biguint_to_felt(left);
    let right = biguint_to_felt(right);
    Ok(felt_to_biguint(pedersen_hash_rs(&left, &right)))
}

#[pyfunction]
fn sign(private_key: BigUint, msg_hash: BigUint, seed: BigUint) -> PyResult<(BigUint, BigUint)> {
    let pk = biguint_to_felt(private_key);
    let msg = biguint_to_felt(msg_hash);
    let seed = biguint_to_felt(seed);
    let k = rfc6979_generate_k_rs(&msg, &pk, Some(&seed));
    let sig = sign_rs(&pk, &msg, &k).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((felt_to_biguint(sig.r), felt_to_biguint(sig.s)))
}

#[pyfunction]
fn verify(public_key: BigUint, msg_hash: BigUint, r: BigUint, s: BigUint) -> PyResult<bool> {
    let pk = biguint_to_felt(public_key);
    let msg = biguint_to_felt(msg_hash);
    let r = biguint_to_felt(r);
    let s = biguint_to_felt(s);
    starknet_crypto::verify(&pk, &msg, &r, &s)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn poseidon_hash(x: BigUint, y: BigUint) -> PyResult<BigUint> {
    let x = biguint_to_felt(x);
    let y = biguint_to_felt(y);
    Ok(felt_to_biguint(poseidon_hash_rs(x, y)))
}

#[pyfunction]
fn poseidon_hash_single(x: BigUint) -> PyResult<BigUint> {
    let x = biguint_to_felt(x);
    Ok(felt_to_biguint(poseidon_hash_single_rs(x)))
}

#[pyfunction]
fn poseidon_hash_many(inputs: Vec<BigUint>) -> PyResult<BigUint> {
    let felts: Vec<Felt> = inputs.into_iter().map(biguint_to_felt).collect();
    Ok(felt_to_biguint(poseidon_hash_many_rs(&felts)))
}

#[pymodule]
fn starknet_crypto_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash_single, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash_many, m)?)?;
    Ok(())
}
