from starknet_crypto_py.starknet_crypto_py import (
    rs_get_public_key,
    rs_pedersen_hash,
    rs_poseidon_hash,
    rs_poseidon_hash_single,
    rs_poseidon_hash_many,
    rs_sign,
    rs_verify,
)


def get_public_key(private_key: int) -> int:
    return int(rs_get_public_key(hex(private_key)))


def pedersen_hash(first: int, second: int) -> int:
    return int(rs_pedersen_hash(hex(first), hex(second)))


def sign(private_key: int, msg_hash: int, seed: int) -> tuple[int, int]:
    (r, s) = rs_sign(hex(private_key), hex(msg_hash), hex(seed))
    return (int(r), int(s))


def verify(public_key: int, msg_hash: int, r: int, s: int) -> bool:
    return rs_verify(hex(public_key), hex(msg_hash), hex(r), hex(s))

def poseidon_hash(x: int, y: int) -> int:
    return int(rs_poseidon_hash(hex(x), hex(y)))

def poseidon_hash_single(x: int) -> int:
    return int(rs_poseidon_hash_single(hex(x)))

def poseidon_hash_many(inputs: list[int]) -> int:
    hex_inputs = [hex(i) for i in inputs]
    return int(rs_poseidon_hash_many(hex_inputs))
