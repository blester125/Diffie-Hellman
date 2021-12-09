"""Tests for Diffie-Hellman Key Exchange."""

from unittest import mock
import pytest
from diffie_hellman import diffie_hellman


PRIMES = frozenset((
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97
))
PRIME_PARAMS = [(i, i in PRIMES) for i in range(101)]


@pytest.mark.parametrize(
    "number,prime",
    PRIME_PARAMS)
def test_is_prime(number, prime):
    maybe_prime, error = diffie_hellman.is_prime(number)
    assert maybe_prime == prime  # Make sure primality was correct.
    # Make sure the found divisor actually divides evenly.
    if error is not None:
        res = number / error.divisor
        assert int(res) == res


PRIMITIVE_ROOTS = {
    5: {2, 3},
    7: {3, 5},
    11: {2, 6, 7, 8},
    13: {2, 6, 7, 11},
    17: {3, 5, 6, 7, 10, 11, 12, 14},
    19: {2, 3, 10, 13, 14, 15},
    23: {5, 7, 10, 11, 14, 15, 17, 19, 20, 21},
    29: {2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27},
    31: {3, 11, 12, 13, 17, 21, 22, 24}
}
ROOT_PARAMS = []
for n, roots in PRIMITIVE_ROOTS.items():
    for i in range(n):
        if i in roots:
            ROOT_PARAMS.append((i, n, True))
        else:
            ROOT_PARAMS.append((i, n, False))


@pytest.mark.parametrize(
    "g,n,root",
    ROOT_PARAMS)
def test_is_primitive_root_modulo_n(g, n, root):
    maybe_root, error = diffie_hellman.is_primitive_root_modulo_n(g, n)
    assert maybe_root == root
    if error is not None:
        current = g ** error.current % n
        prev = g ** error.previous % n
        assert current == prev
        assert current == error.remainder


def test_diffie_hellman_constants_n_0():
    with pytest.raises(ValueError):
        diffie_hellman.DiffieHellmanConstants(g=2, n=0)


def test_diffie_hellman_constants_n_1():
    with pytest.raises(ValueError):
        diffie_hellman.DiffieHellmanConstants(g=2, n=1)


def test_diffie_hellman_constants_n_not_prime():
    with pytest.raises(ValueError):
        diffie_hellman.DiffieHellmanConstants(g=2, n=10)


def test_diffie_hellman_constants_warn_on_n_bit_length():
    with mock.patch("diffie_hellman.diffie_hellman.print") as print_mock:
        diffie_hellman.DiffieHellmanConstants(g=5, n=23)
        print_mock.assert_called_once_with("Warning: n=23 has a bit length of "
                                           "5 which is less than the "
                                           "recommended 2048 bits.")


def test_diffie_hellman_constants_g_not_primitive():
    with pytest.raises(ValueError):
        diffie_hellman.DiffieHellmanConstants(g=4, n=23)


def test_diffie_hellman_constants():
    dh = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    assert dh.g == 5
    assert dh.n == 23


@pytest.mark.parametrize("secret", (-3, 0, -100))
def test_diffie_hellman_secret_less_than_one(secret):
    constant = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    with pytest.raises(ValueError):
        dh = diffie_hellman.DiffieHellman(constant, secret)


@pytest.mark.parametrize("secret", (100, 1000, 20000))
def test_diffie_hellman_secret_greater_than_n(secret):
    constant = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    with pytest.raises(ValueError):
        dh = diffie_hellman.DiffieHellman(constant, secret)


@pytest.mark.parametrize("secret,public", ((4, 4), (3, 10)))
def test_diffie_hellman_public(secret, public):
    constants = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    dh = diffie_hellman.DiffieHellman(constants, secret)
    assert diffie_hellman.calculate_public(dh) == public

@pytest.mark.parametrize("secret,public,shared", ((4, 10, 18), (3, 4, 18)))
def test_diffie_hellman_shared(secret, public, shared):
    constants = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    dh = diffie_hellman.DiffieHellman(constants, secret)
    assert diffie_hellman.calculate_shared(dh, public) == shared


def test_diffie_hellman_different_constants():
    constants = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    constants2 = diffie_hellman.DiffieHellmanConstants(g=7, n=23)

    alice = diffie_hellman.DiffieHellman(constants, 4)
    bob = diffie_hellman.DiffieHellman(constants2, 3)

    with pytest.raises(ValueError):
        diffie_hellman.diffie_hellman(alice, bob)


def test_diffie_hellman():
    constants = diffie_hellman.DiffieHellmanConstants(g=5, n=23)
    alice = diffie_hellman.DiffieHellman(constants, 4)
    bob = diffie_hellman.DiffieHellman(constants, 3)
    assert diffie_hellman.diffie_hellman(alice, bob) == 18
