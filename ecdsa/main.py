#!/usr/bin/env python3
"""
ECDSA Master Script

This script demonstrates the complete ECDSA workflow:
1. Generate a key pair (private and public keys)
2. Sign a message using the private key
3. Verify the signature using the public key
4. Demonstrate signature verification failure with a tampered message

This serves as an educational example of how ECDSA works in practice.
"""

import sys
from typing import Optional

# Import functions from our ECDSA implementation modules
from sign import sign_message
from common import generate_keypair
from verify import verify_signature


def print_separator(title: Optional[str] = None):
    """Print a separator line with an optional title."""
    if title:
        print(f"\n{'=' * 20} {title} {'=' * 20}")
    else:
        print("\n" + "=" * 60)


def demonstrate_ecdsa(message: str) -> None:
    """
    Demonstrate the complete ECDSA workflow with a given message.

    Args:
        message: The message to sign and verify
    """
    print_separator("KEY GENERATION")
    # Step 1: Generate a key pair
    private_key, public_key = generate_keypair()
    print(f"Generated private key: {private_key}")
    print(f"Generated public key: ({public_key[0]}, {public_key[1]})")

    print_separator("SIGNATURE GENERATION")
    # Step 2: Sign the message
    print(f"Message to sign: '{message}'")
    signature = sign_message(message, private_key)
    r, s = signature
    print(f"\nSignature (r, s): ({r}, {s})")

    # Convert to hexadecimal for a more compact representation
    r_hex = hex(r)[2:]
    s_hex = hex(s)[2:]
    print(f"Signature in hex: (0x{r_hex}, 0x{s_hex})")

    print_separator("SIGNATURE VERIFICATION")
    # Step 3: Verify the signature
    is_valid = verify_signature(message, signature, public_key)

    print("\nVerification result:")
    if is_valid:
        print("✓ Signature is VALID")
    else:
        print("✗ Signature is INVALID (This shouldn't happen!)")

    print_separator("TAMPERED MESSAGE VERIFICATION")
    # Step 4: Demonstrate verification failure with a tampered message
    tampered_message = message + " (tampered)"
    print(f"Tampered message: '{tampered_message}'")

    is_valid = verify_signature(tampered_message, signature, public_key)

    print("\nVerification result for tampered message:")
    if is_valid:
        print("✓ Signature is VALID (This shouldn't happen!)")
    else:
        print("✗ Signature is INVALID (Expected for tampered message)")

    # No need to return values as they're not used by the caller


def main():
    """Main function to run the ECDSA demonstration."""
    print("ECDSA Complete Workflow Demonstration")
    print("=" * 60)

    # Get message from command line or use default
    if len(sys.argv) > 1:
        message = " ".join(sys.argv[1:])
    else:
        message = "Hello, ECDSA! This is a secure message."

    # Run the demonstration
    demonstrate_ecdsa(message)

    print_separator("SUMMARY")
    print("The ECDSA workflow demonstrated:")
    print("1. Key Generation: Created a private/public key pair")
    print("2. Signature: Used private key to sign a message")
    print("3. Verification: Used public key to verify the signature")
    print("4. Security: Showed that changing the message invalidates the signature")

    print("\nThis demonstrates the core properties of digital signatures:")
    print("- Authentication: Verifies who created the signature")
    print("- Integrity: Ensures the message hasn't been altered")
    print("- Non-repudiation: Signer cannot deny signing the message")


if __name__ == "__main__":
    main()
