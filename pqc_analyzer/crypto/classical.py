"""
PQC Analyzer - Classical Cryptography Reference Implementations
================================================================
Reference implementations for comparison against PQC:
- RSA-2048/4096 (factoring-vulnerable)
- ECDH P-256/P-384/X25519 (DLOG-vulnerable)
- AES-256 (symmetric - quantum-safe with doubled key)
- SHA-3 (quantum-safe with doubled output)

All implementations use Python's cryptography library for correctness.
Performance profiling is built in for comparative analysis.
"""

import hashlib
import logging
import secrets
import time
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class RSABenchmark:
    """RSA key generation, encryption, and decryption benchmarks."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def benchmark(self, iterations: int = 10) -> Dict:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            return {"error": "cryptography package not installed"}

        keygen_times, encrypt_times, decrypt_times = [], [], []

        for _ in range(iterations):
            # Key generation
            t0 = time.perf_counter()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
            )
            public_key = private_key.public_key()
            keygen_times.append(time.perf_counter() - t0)

            # Encryption (OAEP)
            message = secrets.token_bytes(32)
            t0 = time.perf_counter()
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            encrypt_times.append(time.perf_counter() - t0)

            # Decryption
            t0 = time.perf_counter()
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            decrypt_times.append(time.perf_counter() - t0)
            assert plaintext == message

        def stats(times):
            arr = np.array(times) * 1000
            return {"mean_ms": round(float(arr.mean()), 2), "std_ms": round(float(arr.std()), 2)}

        return {
            "algorithm": f"RSA-{self.key_size}",
            "iterations": iterations,
            "keygen": stats(keygen_times),
            "encrypt": stats(encrypt_times),
            "decrypt": stats(decrypt_times),
            "key_sizes": {
                "public_key_bytes": self.key_size // 8,
                "private_key_bytes": self.key_size // 4,
                "ciphertext_bytes": self.key_size // 8,
            },
            "quantum_vulnerable": True,
            "quantum_attack": f"Shor's algorithm breaks {self.key_size}-bit RSA in polynomial time",
        }


class ECDHBenchmark:
    """ECDH key exchange benchmarks (P-256, P-384, X25519)."""

    def __init__(self, curve: str = "X25519"):
        self.curve = curve

    def benchmark(self, iterations: int = 100) -> Dict:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec, x25519
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            return {"error": "cryptography package not installed"}

        keygen_times, exchange_times = [], []

        for _ in range(iterations):
            if self.curve == "X25519":
                t0 = time.perf_counter()
                alice_key = x25519.X25519PrivateKey.generate()
                alice_pub = alice_key.public_key()
                keygen_times.append(time.perf_counter() - t0)

                bob_key = x25519.X25519PrivateKey.generate()
                bob_pub = bob_key.public_key()

                t0 = time.perf_counter()
                shared1 = alice_key.exchange(bob_pub)
                shared2 = bob_key.exchange(alice_pub)
                exchange_times.append(time.perf_counter() - t0)
                assert shared1 == shared2

            else:
                curve_obj = ec.SECP256R1() if self.curve == "P-256" else ec.SECP384R1()
                t0 = time.perf_counter()
                alice_key = ec.generate_private_key(curve_obj)
                keygen_times.append(time.perf_counter() - t0)
                bob_key = ec.generate_private_key(curve_obj)
                t0 = time.perf_counter()
                shared1 = alice_key.exchange(ec.ECDH(), bob_key.public_key())
                exchange_times.append(time.perf_counter() - t0)

        def stats(times):
            arr = np.array(times) * 1000
            return {"mean_ms": round(float(arr.mean()), 4), "std_ms": round(float(arr.std()), 4)}

        key_sizes = {"X25519": (32, 32, 32), "P-256": (32, 64, 32), "P-384": (48, 96, 48)}
        pk, sk, ss = key_sizes.get(self.curve, (32, 32, 32))

        return {
            "algorithm": f"ECDH-{self.curve}",
            "iterations": iterations,
            "keygen": stats(keygen_times),
            "exchange": stats(exchange_times),
            "key_sizes": {
                "public_key_bytes": pk,
                "private_key_bytes": sk,
                "shared_secret_bytes": ss,
            },
            "quantum_vulnerable": True,
            "quantum_attack": "Shor's algorithm solves ECDLP in O(n³) quantum operations",
        }


class SymmetricBenchmark:
    """AES-256-GCM benchmark (quantum-resistant with 256-bit keys)."""

    def benchmark(self, message_sizes_kb: List[int] = None, iterations: int = 100) -> Dict:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return {"error": "cryptography package not installed"}

        if message_sizes_kb is None:
            message_sizes_kb = [1, 64, 1024]

        results = {}
        for size_kb in message_sizes_kb:
            key = secrets.token_bytes(32)
            aes = AESGCM(key)
            message = secrets.token_bytes(size_kb * 1024)
            times = []
            for _ in range(iterations):
                nonce = secrets.token_bytes(12)
                t0 = time.perf_counter()
                ct = aes.encrypt(nonce, message, None)
                times.append(time.perf_counter() - t0)

            arr = np.array(times) * 1000
            results[f"{size_kb}KB"] = {
                "mean_ms": round(float(arr.mean()), 4),
                "throughput_mbps": round(size_kb / (arr.mean() / 1000) / 1024, 2),
            }

        return {
            "algorithm": "AES-256-GCM",
            "quantum_vulnerable": False,
            "quantum_notes": "Grover's algorithm reduces effective key space to 128 bits (still secure)",
            "results_by_size": results,
        }
