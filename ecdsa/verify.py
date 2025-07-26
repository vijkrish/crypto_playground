#!/usr/bin/env python3
"""
ECDSA Verification Algorithm Implementation

This script demonstrates the ECDSA (Elliptic Curve Digital Signature Algorithm)
verification process as a companion to the signature generation in sign.py.

The verification process follows these steps:
1. Check that r and s are in the range [1, n-1]
2. Compute w = s^(-1) mod n
3. Compute u1 = hw mod n and u2 = rw mod n (where h is the hash of the message)
4. Compute the point (x, y) = u1*G + u2*Q (where G is the generator point and Q is the public key)
5. Verify that r = x mod n
"""

from typing import Tuple

# Import utility functions and constants from util.py
from util import G_x, G_y, hash_message, mod_inverse, n, point_add, scalar_multiply


def verify_signature(
    message: str, signature: Tuple[int, int], public_key: Tuple[int, int]
) -> bool:
    """
    Verify an ECDSA signature.

    Args:
        message: The message that was signed
        signature: The signature as a tuple (r, s)
        public_key: The public key as a point (x, y)

    Returns:
        True if the signature is valid, False otherwise
    """
    r, s = signature

    # Step 1: Check that r and s are in the range [1, n-1]
    if not (1 <= r < n and 1 <= s < n):
        print("Step 1: Signature values r or s are out of range [1, n-1]")
        return False
    print(f"Step 1: Verified r and s are in range [1, n-1]")

    # Step 2: Hash the message to get h
    h = hash_message(message)
    print(f"Step 2: Hash the message to get h = {h}")

    # Step 3: Compute w = s^(-1) mod n
    w = mod_inverse(s, n)
    print(f"Step 3: Compute w = s^(-1) mod n = {w}")

    # Step 4: Compute u1 = hw mod n and u2 = rw mod n
    u1 = (h * w) % n
    u2 = (r * w) % n
    print(f"Step 4: Compute u1 = hw mod n = {u1}")
    print(f"        Compute u2 = rw mod n = {u2}")

    # Step 5: Compute the point (x, y) = u1*G + u2*Q
    point1 = scalar_multiply(u1, (G_x, G_y))
    point2 = scalar_multiply(u2, public_key)

    if point1 is None or point2 is None:
        print("Step 5: Point multiplication resulted in the point at infinity")
        return False

    point_sum = point_add(point1, point2)

    if point_sum is None:
        print("Step 5: Point addition resulted in the point at infinity")
        return False

    x, y = point_sum
    print(f"Step 5: Compute (x, y) = u1*G + u2*Q = ({x}, {y})")

    # Step 6: Verify that r = x mod n
    v = x % n
    print(f"Step 6: Compute v = x mod n = {v}")
    print(f"        Check if v == r: {v} {'==' if v == r else '!='} {r}")

    # The signature is valid if v = r
    return v == r
