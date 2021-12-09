"""A simple implementation of Diffie-Hellman Key Exchange."""

import dataclasses
from typing import Tuple, Optional


RECOMMENDED_N_BIT_LENGTH = 2048  # From https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Practical_attacks_on_Internet_traffic


@dataclasses.dataclass
class PrimeError:
    """Error message info for when n is not prime."""
    divisor: int


def is_prime(n: int) -> Tuple[bool, Optional[PrimeError]]:
    """Based on https://en.wikipedia.org/wiki/Primality_test#Python"""
    if n <= 3:
        return n > 1, None  # Zero is not prime
    if n % 2 == 0:  # Catch evens
        return False, PrimeError(2)
    if n % 3 == 0:  # Catch divs by 3
        return False, PrimeError(3)
    i = 5
    while i ** 2 <= n:  # Only need to check up to √n, sieve of eratosthenes
        if n % i == 0:
            return False, PrimeError(i)
        if n % (i + 2) == 0:
            return False, PrimeError(i + 2)
        i += 6
    return True, None  # We never found a divisor so it is prime


@dataclasses.dataclass
class PrimitiveRootError:
    """Error message info for when g is not a primitive root factor of n."""
    current: int
    remainder: int
    previous: int


def is_primitive_root_modulo_n(
        g: int,
        n: int
) -> Tuple[bool, Optional[PrimitiveRootError]]:
    """Check that g is a primitive root module n."""
    remainders = {}
    for i in range(n - 1):
        remainder = g ** i % n
        if remainder in remainders:
            return False, PrimitiveRootError(i,
                                             remainder,
                                             remainders[remainder])
        remainders[remainder] = i
    return True, None


@dataclasses.dataclass
class DiffieHellmanConstants:
    g: int  # What we raise to our secret
    n: int  # What we modulo by

    def __post_init__(self):
        # Make sure n is prime
        prime, error = is_prime(self.n)
        if not prime:
            if self.n == 0:
                raise ValueError("n cannot be zero, it isn't even prime.")
            if self.n == 1:
                raise ValueError("n cannot be one, it isn't even prime.")
            raise ValueError(f"n={self.n} needs to be prime, found {self.n} / "
                             f"{error.divisor} = {self.n // error.divisor}")
        # Warn about the security of N
        if self.n.bit_length() < RECOMMENDED_N_BIT_LENGTH:
            print(f"Warning: n={self.n} has a bit length of "
                  f"{self.n.bit_length()} which is less than the recommended "
                  f"{RECOMMENDED_N_BIT_LENGTH} bits.")
        # Check that g is a primitive root modulo n
        root, error = is_primitive_root_modulo_n(self.g, self.n)
        if not root:
            raise ValueError(f"g={self.g} is not a primitive root module "
                             f"n={self.n}, "
                             f"g**{error.current}%n={error.remainder} which "
                             "was already found at "
                             f"g**{error.previous}%n.")


@dataclasses.dataclass
class DiffieHellman:
    constants: DiffieHellmanConstants
    secret: int

    def __post_init__(self):
        # Check that secret is in the bound [1, n]
        if self.secret < 1:
            raise ValueError(f"secret={self.secret} needs to be at least 1")
        if self.secret > self.constants.n:
            raise ValueError(f"secret={self.secret} needs to be less than "
                             f"n={self.constants.n}")


def calculate_public(dh: DiffieHellman) -> int:
    """Calculate g ** (a|b) mod n."""
    return dh.constants.g ** dh.secret % dh.constants.n


def calculate_shared(dh: DiffieHellman, public: int) -> int:
    """Calculate (g ** (a|b) mod n) ** (b|a) mod n."""
    return public ** dh.secret % dh.constants.n


def diffie_hellman(alice: DiffieHellman, bob: DiffieHellman):
    if alice.constants != bob.constants:
        raise ValueError("Alice and Bob need to be using the same "
                         "DiffieHellmanConstants, got: "
                         f"Alice={alice.constants}, Bob={bob.constants}")

    alice_public = calculate_public(alice)  # g ** a % n
    print(f"Alice's Public Value: {alice_public}")
    bob_public = calculate_public(bob)  # g ** b % n
    print(f"Bob's   Public Value: {bob_public}")

    # (g ** b % n) ** a -> g ** (a * b) % n
    alice_shared = calculate_shared(alice, bob_public)
    # (g ** a % n) ** b -> g ** (a * b) % n
    bob_shared = calculate_shared(bob, alice_public)

    assert alice_shared == bob_shared

    return alice_shared


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Simple Diffie-Hellman Key Exchange.")
    parser.add_argument(
        "--n",
        type=int,
        default=23,
        help="A large prime used for modulo calculations, should be at least "
             f"{RECOMMENDED_N_BIT_LENGTH} bits.")
    parser.add_argument(
        "--g",
        type=int,
        default=5,
        help="A primitive root modulo `--n`, will be used as the base in "
             "several exponentiations, in practice can be kept small.")
    parser.add_argument(
        "--alice",
        type=int,
        default=4,
        help="Alice's secret number, can be random between 1 and `--n`.")
    parser.add_argument(
        "--bob",
        type=int,
        default=3,
        help="Bob's secret number, can be random between 1 and `--n.`")
    args = parser.parse_args()

    constants = DiffieHellmanConstants(g=args.g, n=args.n)
    print(f"Shared Constants: {constants}")
    alice = DiffieHellman(constants=constants, secret=args.alice)
    print(f"Alice: {alice}")
    bob = DiffieHellman(constants=constants, secret=args.bob)
    print(f"Bob:   {bob}")
    print(f"Agreed upon shared secret: {diffie_hellman(alice, bob)}")
