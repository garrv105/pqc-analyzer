"""
PQC Analyzer - CRYSTALS-Kyber Implementation
=============================================
Pure Python implementation of CRYSTALS-Kyber (NIST PQC Standard, FIPS 203).
Kyber is a lattice-based Key Encapsulation Mechanism (KEM) based on
the Module Learning With Errors (MLWE) problem.

Security levels implemented:
  - Kyber-512  (k=2, ~128-bit security, Category 1)
  - Kyber-768  (k=3, ~192-bit security, Category 3)
  - Kyber-1024 (k=4, ~256-bit security, Category 5)

This implementation is for RESEARCH AND ANALYSIS purposes.
Do NOT use this in production — use liboqs or PQClean instead.

References:
  - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
  - Crystals-Kyber specification v3.02
"""

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Kyber parameters
# ---------------------------------------------------------------------------


@dataclass
class KyberParams:
    """Complete parameter set for a Kyber security level."""

    name: str
    k: int  # Module rank
    n: int = 256  # Polynomial degree
    q: int = 3329  # Modulus
    eta1: int = 2  # Noise distribution parameter (KeyGen)
    eta2: int = 2  # Noise distribution parameter (Encap)
    du: int = 10  # Ciphertext compression bits (u)
    dv: int = 4  # Ciphertext compression bits (v)
    security_level: int = 0  # NIST category (1/3/5)

    @property
    def public_key_bytes(self) -> int:
        return 32 * self.k * 12 // 8 + 32  # ek = t_hat bytes + rho

    @property
    def private_key_bytes(self) -> int:
        return 32 * self.k * 12 // 8  # dk = s bytes

    @property
    def ciphertext_bytes(self) -> int:
        u_bytes = self.k * self.n * self.du // 8
        v_bytes = self.n * self.dv // 8
        return u_bytes + v_bytes

    @property
    def shared_secret_bytes(self) -> int:
        return 32


KYBER_512 = KyberParams(name="Kyber-512", k=2, eta1=3, eta2=2, du=10, dv=4, security_level=1)
KYBER_768 = KyberParams(name="Kyber-768", k=3, eta1=2, eta2=2, du=10, dv=4, security_level=3)
KYBER_1024 = KyberParams(name="Kyber-1024", k=4, eta1=2, eta2=2, du=11, dv=5, security_level=5)

KYBER_VARIANTS = {
    "Kyber-512": KYBER_512,
    "Kyber-768": KYBER_768,
    "Kyber-1024": KYBER_1024,
}


# ---------------------------------------------------------------------------
# Mathematical primitives
# ---------------------------------------------------------------------------


class KyberMath:
    """Core Number Theoretic Transform (NTT) and polynomial arithmetic."""

    Q = 3329
    # NTT root of unity: zeta = 17 (primitive 256-th root mod Q)
    ZETA = 17
    # Precomputed powers of zeta (bit-reversed order)
    _zetas = None

    @classmethod
    def get_zetas(cls) -> np.ndarray:
        if cls._zetas is None:
            zetas = np.zeros(128, dtype=np.int64)
            for i in range(128):
                zetas[i] = pow(cls.ZETA, cls._bit_rev(i, 7), cls.Q)
            cls._zetas = zetas
        return cls._zetas

    @staticmethod
    def _bit_rev(n: int, bits: int) -> int:
        result = 0
        for _ in range(bits):
            result = (result << 1) | (n & 1)
            n >>= 1
        return result

    @classmethod
    def ntt(cls, f: np.ndarray) -> np.ndarray:
        """Number Theoretic Transform (in-place, returns new array)."""
        f = f.copy().astype(np.int64)
        zetas = cls.get_zetas()
        k = 1
        length = 128
        while length >= 2:
            for start in range(0, 256, 2 * length):
                zeta = zetas[k]
                k += 1
                for j in range(start, start + length):
                    t = (zeta * f[j + length]) % cls.Q
                    f[j + length] = (f[j] - t) % cls.Q
                    f[j] = (f[j] + t) % cls.Q
            length //= 2
        return f

    @classmethod
    def inv_ntt(cls, f: np.ndarray) -> np.ndarray:
        """Inverse NTT."""
        f = f.copy().astype(np.int64)
        zetas = cls.get_zetas()
        k = 127
        length = 2
        while length <= 128:
            for start in range(0, 256, 2 * length):
                zeta = zetas[k]
                k -= 1
                for j in range(start, start + length):
                    t = f[j]
                    f[j] = (t + f[j + length]) % cls.Q
                    f[j + length] = (zeta * (f[j + length] - t)) % cls.Q
            length *= 2
        f_inv = pow(128, cls.Q - 2, cls.Q)  # 128^{-1} mod Q
        return (f * f_inv) % cls.Q

    @classmethod
    def poly_mul_ntt(cls, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Pointwise multiplication in NTT domain."""
        return (a * b) % cls.Q

    @classmethod
    def compress(cls, x: np.ndarray, d: int) -> np.ndarray:
        """Compress polynomial coefficients to d bits."""
        factor = 1 << d
        return np.round(x * factor / cls.Q).astype(np.int64) % factor

    @classmethod
    def decompress(cls, x: np.ndarray, d: int) -> np.ndarray:
        """Decompress polynomial coefficients from d bits."""
        factor = 1 << d
        return np.round(x * cls.Q / factor).astype(np.int64) % cls.Q

    @classmethod
    def cbd(cls, eta: int, seed: bytes) -> np.ndarray:
        """
        Centered Binomial Distribution sampling.
        Used for small-norm noise polynomials.
        """
        buf = cls._prf(seed, 2 * 256 * eta // 8)
        bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8))
        bits = bits.reshape(-1, 2 * eta)
        a = bits[:, :eta].sum(axis=1)
        b = bits[:, eta:].sum(axis=1)
        return (a - b).astype(np.int64) % cls.Q

    @staticmethod
    def _prf(seed: bytes, length: int) -> bytes:
        """Pseudorandom function using SHAKE-256."""
        import hashlib

        h = hashlib.shake_256(seed)
        return h.digest(length)

    @staticmethod
    def xof(rho: bytes, i: int, j: int, length: int) -> bytes:
        """XOF for matrix generation (SHAKE-128)."""
        import hashlib

        seed = rho + bytes([i, j])
        h = hashlib.shake_128(seed)
        return h.digest(length)

    @classmethod
    def sample_ntt(cls, seed: bytes) -> np.ndarray:
        """Sample a polynomial uniform over Rq using rejection sampling."""
        coeffs = []
        raw = bytearray(seed)
        extra = hashlib.shake_128(seed).digest(3 * 256)
        raw = extra
        i = 0
        while len(coeffs) < 256:
            if i + 2 >= len(raw):
                break
            d1 = raw[i] + 256 * (raw[i + 1] % 16)
            d2 = raw[i + 1] // 16 + 16 * raw[i + 2]
            i += 3
            if d1 < cls.Q:
                coeffs.append(d1)
            if d2 < cls.Q and len(coeffs) < 256:
                coeffs.append(d2)
        return np.array(coeffs[:256], dtype=np.int64)


# ---------------------------------------------------------------------------
# Kyber KEM
# ---------------------------------------------------------------------------


class KyberKEM:
    """
    CRYSTALS-Kyber Key Encapsulation Mechanism.

    Implements ML-KEM as specified in FIPS 203 (draft).
    Supports all three security levels (512/768/1024).
    """

    def __init__(self, params: KyberParams):
        self.params = params
        self.math = KyberMath()
        self._keygen_times: List[float] = []
        self._encap_times: List[float] = []
        self._decap_times: List[float] = []

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate a Kyber key pair.

        Returns:
            (public_key, private_key)
        """
        t0 = time.perf_counter()
        k = self.params.k
        # Random seeds
        d = secrets.token_bytes(32)
        rho, sigma = hashlib.sha3_512(d).digest()[:32], hashlib.sha3_512(d).digest()[32:]

        # Generate matrix A_hat in NTT domain
        A_hat = self._gen_matrix(rho, k, transpose=False)

        # Sample secret and error polynomials
        s = self._sample_poly_vec(sigma, k, self.params.eta1, offset=0)
        e = self._sample_poly_vec(sigma, k, self.params.eta1, offset=k)

        # NTT of secret
        s_hat = [self.math.ntt(si) for si in s]
        e_hat = [self.math.ntt(ei) for ei in e]

        # t_hat = A_hat * s_hat + e_hat
        t_hat = self._mat_vec_mul(A_hat, s_hat, k)
        t_hat = [(t_hat[i] + e_hat[i]) % self.math.Q for i in range(k)]

        # Serialize
        ek = self._serialize_poly_vec(t_hat, 12) + rho
        dk = self._serialize_poly_vec(s_hat, 12)

        elapsed = time.perf_counter() - t0
        self._keygen_times.append(elapsed)
        return ek, dk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret.

        Args:
            public_key: recipient's public key

        Returns:
            (ciphertext, shared_secret)
        """
        t0 = time.perf_counter()
        k = self.params.k
        rho = public_key[-32:]
        t_hat = self._deserialize_poly_vec(public_key[:-32], k, 12)

        A_hat = self._gen_matrix(rho, k, transpose=True)

        # Random message
        m = secrets.token_bytes(32)
        r_seed = hashlib.sha3_256(m + hashlib.sha3_256(public_key).digest()).digest()

        r = self._sample_poly_vec(r_seed, k, self.params.eta1, offset=0)
        e1 = self._sample_poly_vec(r_seed, k, self.params.eta2, offset=k)
        e2_seed = r_seed + bytes([2 * k])
        e2 = self.math.cbd(self.params.eta2, e2_seed)

        r_hat = [self.math.ntt(ri) for ri in r]

        # u = A^T * r + e1
        u = self._mat_vec_mul(A_hat, r_hat, k)
        u = [self.math.inv_ntt((u[i] + self.math.ntt(e1[i])) % self.math.Q) for i in range(k)]

        # v = t^T * r + e2 + round(q/2) * m
        m_poly = self._decode_message(m)
        t_r = np.zeros(256, dtype=np.int64)
        for i in range(k):
            t_r = (t_r + self.math.inv_ntt(self.math.poly_mul_ntt(t_hat[i], r_hat[i]))) % self.math.Q
        v = (t_r + e2 + m_poly) % self.math.Q

        # Compress
        u_c = np.concatenate([self.math.compress(ui, self.params.du) for ui in u])
        v_c = self.math.compress(v, self.params.dv)

        ct = self._pack_bits(u_c, self.params.du) + self._pack_bits(v_c, self.params.dv)
        ss = hashlib.sha3_256(m).digest()

        elapsed = time.perf_counter() - t0
        self._encap_times.append(elapsed)
        return ct, ss

    def decapsulate(self, private_key: bytes, public_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate to recover the shared secret.

        Args:
            private_key: recipient's private key
            public_key: recipient's public key
            ciphertext: ciphertext from encapsulate()

        Returns:
            shared_secret (32 bytes)
        """
        t0 = time.perf_counter()
        k = self.params.k
        s_hat = self._deserialize_poly_vec(private_key, k, 12)

        # Unpack ciphertext
        u_bytes = k * 256 * self.params.du // 8
        u_c = self._unpack_bits(ciphertext[:u_bytes], 256 * k, self.params.du)
        v_c = self._unpack_bits(ciphertext[u_bytes:], 256, self.params.dv)

        u = [self.math.decompress(u_c[i * 256 : (i + 1) * 256], self.params.du) for i in range(k)]
        v = self.math.decompress(v_c, self.params.dv)

        # m' = v - s^T * u
        u_hat = [self.math.ntt(ui) for ui in u]
        s_u = np.zeros(256, dtype=np.int64)
        for i in range(k):
            s_u = (s_u + self.math.inv_ntt(self.math.poly_mul_ntt(s_hat[i], u_hat[i]))) % self.math.Q

        m_poly = (v - s_u) % self.math.Q
        m = self._encode_message(m_poly)
        ss = hashlib.sha3_256(m).digest()

        elapsed = time.perf_counter() - t0
        self._decap_times.append(elapsed)
        return ss

    def benchmark(self, iterations: int = 100) -> Dict:
        """Run performance benchmark across all operations."""
        self._keygen_times.clear()
        self._encap_times.clear()
        self._decap_times.clear()

        for _ in range(iterations):
            ek, dk = self.keygen()
            ct, ss1 = self.encapsulate(ek)
            ss2 = self.decapsulate(dk, ek, ct)
            assert ss1 == ss2, "Correctness check failed!"

        def stats(times):
            arr = np.array(times) * 1000  # ms
            return {
                "mean_ms": round(float(arr.mean()), 4),
                "std_ms": round(float(arr.std()), 4),
                "min_ms": round(float(arr.min()), 4),
                "max_ms": round(float(arr.max()), 4),
            }

        return {
            "variant": self.params.name,
            "security_level": self.params.security_level,
            "iterations": iterations,
            "keygen": stats(self._keygen_times),
            "encapsulate": stats(self._encap_times),
            "decapsulate": stats(self._decap_times),
            "key_sizes": {
                "public_key_bytes": self.params.public_key_bytes,
                "private_key_bytes": self.params.private_key_bytes,
                "ciphertext_bytes": self.params.ciphertext_bytes,
                "shared_secret_bytes": self.params.shared_secret_bytes,
            },
        }

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _gen_matrix(self, rho: bytes, k: int, transpose: bool) -> List[List[np.ndarray]]:
        """Generate public matrix A (or A^T)."""
        A = []
        for i in range(k):
            row = []
            for j in range(k):
                ii, jj = (j, i) if transpose else (i, j)
                seed = self.math.xof(rho, ii, jj, 3 * 256)
                row.append(self.math.sample_ntt(seed))
            A.append(row)
        return A

    def _sample_poly_vec(self, seed: bytes, k: int, eta: int, offset: int) -> List[np.ndarray]:
        return [self.math.cbd(eta, seed + bytes([offset + i])) for i in range(k)]

    def _mat_vec_mul(self, A: List[List[np.ndarray]], v: List[np.ndarray], k: int) -> List[np.ndarray]:
        result = []
        for i in range(k):
            acc = np.zeros(256, dtype=np.int64)
            for j in range(k):
                acc = (acc + self.math.poly_mul_ntt(A[i][j], v[j])) % self.math.Q
            result.append(acc)
        return result

    def _serialize_poly_vec(self, polys: List[np.ndarray], bits: int) -> bytes:
        out = b""
        for p in polys:
            out += self._pack_bits(p, bits)
        return out

    def _deserialize_poly_vec(self, data: bytes, k: int, bits: int) -> List[np.ndarray]:
        size = 256 * bits // 8
        return [self._unpack_bits(data[i * size : (i + 1) * size], 256, bits) for i in range(k)]

    def _pack_bits(self, poly: np.ndarray, bits: int) -> bytes:
        mask = (1 << bits) - 1
        coeffs = (poly & mask).astype(np.uint64)
        buf = bytearray()
        bit_buf = 0
        bit_count = 0
        for c in coeffs:
            bit_buf |= int(c) << bit_count
            bit_count += bits
            while bit_count >= 8:
                buf.append(bit_buf & 0xFF)
                bit_buf >>= 8
                bit_count -= 8
        if bit_count > 0:
            buf.append(bit_buf & 0xFF)
        return bytes(buf)

    def _unpack_bits(self, data: bytes, n: int, bits: int) -> np.ndarray:
        mask = (1 << bits) - 1
        coeffs = []
        bit_buf = 0
        bit_count = 0
        idx = 0
        for _ in range(n):
            while bit_count < bits and idx < len(data):
                bit_buf |= data[idx] << bit_count
                bit_count += 8
                idx += 1
            coeffs.append(bit_buf & mask)
            bit_buf >>= bits
            bit_count -= bits
        return np.array(coeffs, dtype=np.int64)

    def _decode_message(self, m: bytes) -> np.ndarray:
        """Encode 32-byte message as polynomial (bit expansion)."""
        bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8), bitorder="little")
        scale = np.int64((self.math.Q + 1) // 2)
        return bits[:256].astype(np.int64) * scale

    def _encode_message(self, poly: np.ndarray) -> bytes:
        """Decode polynomial to 32-byte message."""
        scaled = (2 * poly + self.math.Q // 2) // self.math.Q
        bits = (scaled % 2).astype(np.uint8)[:256]
        return np.packbits(bits, bitorder="little").tobytes()[:32]
