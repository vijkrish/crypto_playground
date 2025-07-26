#!/usr/bin/env python3
"""
ECDSA Common Functions and Constants

This module contains common utility functions and constants used by both
the ECDSA signature generation and verification algorithms.
"""

import hashlib
import random
from typing import Optional, Tuple

# NIST P-256 curve parameters (Taken from https://neuromancer.sk/std/nist/P-256)
# p: The prime that defines the field
# a, b: The curve parameters in the equation y^2 = x^3 + ax + b
# G_x, G_y: The generator point coordinates
# n: The order of the generator point
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
G_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def mod_inverse(k: int, p: int) -> int:
    """
    Calculate the modular multiplicative inverse of k modulo p.
    This is used in the elliptic curve point addition formula.

    Args:
        k: The number to find the inverse for
        p: The modulus

    Returns:
        The modular multiplicative inverse of k
    """
    # Extended Euclidean Algorithm to find modular inverse
    if k == 0:
        raise ZeroDivisionError("Division by zero")

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - mod_inverse(-k, p)

    # Initialize values for extended Euclidean algorithm
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # Check if gcd(k, p) = 1
    if old_r != 1:
        raise ValueError(f"{k} has no multiplicative inverse modulo {p}")

    return old_s % p


def point_add(
    P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]
) -> Optional[Tuple[int, int]]:
    """
    Add two points on the elliptic curve y^2 = x^3 + ax + b.

    Args:
        P1: First point (x1, y1)
        P2: Second point (x2, y2)

    Returns:
        The sum of P1 and P2 on the curve
    """
    # Handle the case where one point is the point at infinity (None)
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    # If the points are the same, use point doubling formula
    if x1 == x2 and y1 == y2:
        return point_double(P1)

    # If the points have the same x-coordinate but different y-coordinates,
    # the result is the point at infinity
    if x1 == x2:
        return None

    # Calculate the slope of the line through P1 and P2
    slope = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p

    # Calculate the coordinates of the sum point
    x3 = (slope**2 - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p

    return (x3, y3)


def point_double(P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """
    Double a point on the elliptic curve y^2 = x^3 + ax + b.

    Args:
        P: The point (x, y) to double

    Returns:
        The result of P + P on the curve
    """
    if P is None:
        return None

    x, y = P

    # If y is 0, the tangent is vertical and the result is the point at infinity
    if y == 0:
        return None

    # Calculate the slope of the tangent line at P
    # slope = (3x^2 + a) / (2y)
    slope = ((3 * x**2 + a) * mod_inverse(2 * y, p)) % p

    # Calculate the coordinates of the doubled point
    x3 = (slope**2 - 2 * x) % p
    y3 = (slope * (x - x3) - y) % p

    return (x3, y3)


def scalar_multiply(k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """
    Multiply a point P by a scalar k using the double-and-add algorithm.
    This computes kP on the elliptic curve.

    Args:
        k: The scalar multiplier
        P: The point to multiply

    Returns:
        The result of kP on the curve
    """
    # Handle special cases
    if k == 0 or P is None:
        return None

    if k < 0:
        # Negating a point on an elliptic curve means negating its y-coordinate
        x, y = P
        return scalar_multiply(-k, (x, (-y) % p))

    # Double-and-add algorithm for efficient point multiplication
    result = None
    addend = P

    while k:
        if k & 1:  # If the least significant bit of k is 1
            result = point_add(result, addend)

        # Double the point
        addend = point_double(addend)

        # Shift k right by 1 bit
        k >>= 1

    return result


def hash_message(message: str) -> int:
    """
    Hash a message using SHA-256 and convert the hash to an integer.

    Args:
        message: The message to hash

    Returns:
        The hash value as an integer between 0 and n-1
    """
    # Hash the message using SHA-256
    hash_obj = hashlib.sha256(message.encode("utf-8"))
    hash_bytes = hash_obj.digest()

    # Convert the hash to an integer
    hash_int = int.from_bytes(hash_bytes, byteorder="big")

    # Ensure the hash is in the range [0, n-1]
    return hash_int % n


def generate_keypair() -> Tuple[int, Tuple[int, int]]:
    """
    Generate a new ECDSA key pair.

    Returns:
        A tuple (private_key, public_key) where public_key is a point (x, y)
    """
    # Generate a random private key d in the range [1, n-2]
    private_key = random.randint(1, n - 2)

    # Compute the public key as Q = dG
    public_key = scalar_multiply(private_key, (G_x, G_y))

    # In the extremely unlikely case that scalar_multiply returns None,
    # try again with a different private key
    while public_key is None:
        private_key = random.randint(1, n - 2)
        public_key = scalar_multiply(private_key, (G_x, G_y))

    return private_key, public_key
