#!/usr/bin/env python3
"""
ECDSA Signature Algorithm Implementation

This script demonstrates the ECDSA (Elliptic Curve Digital Signature Algorithm)
signature generation process based on the description from "Serious Cryptography" book.

The signature generation process follows these steps:
1. Hash the message using a cryptographic hash function
2. Pick a random number k between 1 and n-1 (where n is the curve order)
3. Compute kG (where G is the generator point of the curve)
4. Set r = x mod n (where x is the x-coordinate of kG)
5. Compute s = (h + rd) / k mod n (where h is the hash, d is the private key)
6. The signature is the pair (r, s)
"""

import random
from typing import Tuple

# Import utility functions and constants from common.py
from common import G_x, G_y, hash_message, mod_inverse, n, scalar_multiply


def sign_message(message: str, private_key: int) -> Tuple[int, int]:
    """
    Sign a message using ECDSA.

    Args:
        message: The message to sign
        private_key: The private key d

    Returns:
        The signature as a tuple (r, s)
    """
    # Step 1: Hash the message
    h = hash_message(message)
    print(f"Step 1: Hash the message to get h = {h}")

    while True:
        # Step 2: Generate a random number k between 1 and n-1
        k = random.randint(1, n - 1)
        print(f"Step 2: Generate random k = {k}")

        # Step 3: Compute kG, a point on the curve
        kG = scalar_multiply(k, (G_x, G_y))
        if kG is None:
            continue  # In the unlikely case kG is the point at infinity

        x, y = kG
        print(f"Step 3: Compute kG = ({x}, {y})")

        # Step 4: Set r = x mod n
        r = x % n
        print(f"Step 4: Set r = x mod n = {r}")

        # If r = 0, we need to try again with a different k
        if r == 0:
            print("r = 0, trying again with a different k")
            continue

        # Step 5: Compute s = (h + rd) / k mod n
        s = (mod_inverse(k, n) * (h + r * private_key)) % n
        print(f"Step 5: Compute s = (h + rd) / k mod n = {s}")

        # If s = 0, we need to try again with a different k
        if s == 0:
            print("s = 0, trying again with a different k")
            continue

        # Step 6: Return the signature (r, s)
        print(f"Step 6: The signature is (r, s) = ({r}, {s})")
        return r, s
