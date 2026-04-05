"""
Tests: CRYSTALS-Kyber KEM — correctness, serialization, benchmark structure
"""

import numpy as np
import pytest

from pqc_analyzer.crypto.kyber import KYBER_512, KYBER_768, KYBER_1024, KYBER_VARIANTS, KyberKEM, KyberMath, KyberParams


class TestKyberMath:
    def test_ntt_inverse_roundtrip(self):
        """NTT followed by inverse NTT should return original polynomial."""
        rng = np.random.default_rng(0)
        f = rng.integers(0, KyberMath.Q, size=256).astype(np.int64)
        f_ntt = KyberMath.ntt(f)
        f_recovered = KyberMath.inv_ntt(f_ntt)
        np.testing.assert_array_equal(f % KyberMath.Q, f_recovered % KyberMath.Q)

    def test_ntt_different_from_input(self):
        f = np.arange(256, dtype=np.int64)
        f_ntt = KyberMath.ntt(f)
        assert not np.array_equal(f, f_ntt)

    def test_compress_decompress_approximate(self):
        """Compress+Decompress introduces bounded rounding error."""
        rng = np.random.default_rng(42)
        x = rng.integers(0, KyberMath.Q, size=256).astype(np.int64)
        for d in [4, 10, 11]:
            compressed = KyberMath.compress(x, d)
            decompressed = KyberMath.decompress(compressed, d)
            # Decompressed should be within q/2^(d+1) of original
            error = np.abs((decompressed - x + KyberMath.Q // 2) % KyberMath.Q - KyberMath.Q // 2)
            assert error.max() <= KyberMath.Q // (1 << d) + 1

    def test_cbd_output_range(self):
        import secrets

        seed = secrets.token_bytes(64)
        poly = KyberMath.cbd(eta=2, seed=seed)
        assert len(poly) == 256
        # CBD output should be small (within ±eta range after mod Q)
        centered = np.where(poly > KyberMath.Q // 2, poly - KyberMath.Q, poly)
        assert centered.max() <= 2
        assert centered.min() >= -2

    def test_zetas_correct_length(self):
        zetas = KyberMath.get_zetas()
        assert len(zetas) == 128

    def test_sample_ntt_in_range(self):
        import secrets

        seed = secrets.token_bytes(32)
        poly = KyberMath.sample_ntt(seed)
        assert len(poly) == 256
        assert (poly >= 0).all() and (poly < KyberMath.Q).all()

    def test_poly_mul_ntt_commutativity(self):
        rng = np.random.default_rng(7)
        a = rng.integers(0, KyberMath.Q, 256).astype(np.int64)
        b = rng.integers(0, KyberMath.Q, 256).astype(np.int64)
        ab = KyberMath.poly_mul_ntt(a, b)
        ba = KyberMath.poly_mul_ntt(b, a)
        np.testing.assert_array_equal(ab, ba)


class TestKyberParams:
    @pytest.mark.parametrize("params", [KYBER_512, KYBER_768, KYBER_1024])
    def test_param_fields_positive(self, params):
        assert params.k > 0
        assert params.n == 256
        assert params.q == 3329
        assert params.public_key_bytes > 0
        assert params.private_key_bytes > 0
        assert params.ciphertext_bytes > 0
        assert params.shared_secret_bytes == 32

    def test_kyber_1024_larger_than_768(self):
        assert KYBER_1024.public_key_bytes > KYBER_768.public_key_bytes
        assert KYBER_768.public_key_bytes > KYBER_512.public_key_bytes

    def test_security_levels(self):
        assert KYBER_512.security_level == 1
        assert KYBER_768.security_level == 3
        assert KYBER_1024.security_level == 5

    def test_all_variants_in_dict(self):
        assert "Kyber-512" in KYBER_VARIANTS
        assert "Kyber-768" in KYBER_VARIANTS
        assert "Kyber-1024" in KYBER_VARIANTS


class TestKyberKEMCorrectness:
    @pytest.mark.parametrize(
        "params,name",
        [
            (KYBER_512, "Kyber-512"),
            (KYBER_768, "Kyber-768"),
            (KYBER_1024, "Kyber-1024"),
        ],
    )
    def test_encap_decap_correctness(self, params, name):
        """Encapsulated and decapsulated shared secrets must match."""
        kem = KyberKEM(params)
        for trial in range(5):
            ek, dk = kem.keygen()
            ct, ss1 = kem.encapsulate(ek)
            ss2 = kem.decapsulate(dk, ek, ct)
            assert ss1 == ss2, f"{name} trial {trial}: shared secrets differ"

    def test_shared_secret_length(self):
        kem = KyberKEM(KYBER_768)
        ek, dk = kem.keygen()
        _, ss = kem.encapsulate(ek)
        assert len(ss) == 32

    def test_different_keys_different_secrets(self):
        kem = KyberKEM(KYBER_512)
        ek1, dk1 = kem.keygen()
        ek2, dk2 = kem.keygen()
        _, ss1 = kem.encapsulate(ek1)
        _, ss2 = kem.encapsulate(ek2)
        assert ss1 != ss2

    def test_wrong_key_gives_wrong_secret(self):
        kem = KyberKEM(KYBER_512)
        ek1, dk1 = kem.keygen()
        ek2, dk2 = kem.keygen()
        ct, ss_correct = kem.encapsulate(ek1)
        ss_wrong = kem.decapsulate(dk2, ek1, ct)  # Wrong private key
        assert ss_correct != ss_wrong

    def test_keygen_key_lengths(self):
        for params in [KYBER_512, KYBER_768, KYBER_1024]:
            kem = KyberKEM(params)
            ek, dk = kem.keygen()
            assert len(dk) == params.private_key_bytes

    def test_ciphertext_length(self):
        for params in [KYBER_512, KYBER_768, KYBER_1024]:
            kem = KyberKEM(params)
            ek, _ = kem.keygen()
            ct, _ = kem.encapsulate(ek)
            assert len(ct) == params.ciphertext_bytes

    def test_public_key_length(self):
        for params in [KYBER_512, KYBER_768, KYBER_1024]:
            kem = KyberKEM(params)
            ek, _ = kem.keygen()
            assert len(ek) == params.public_key_bytes


class TestKyberBenchmark:
    def test_benchmark_returns_correct_keys(self):
        kem = KyberKEM(KYBER_512)
        result = kem.benchmark(iterations=5)
        required = ["variant", "security_level", "iterations", "keygen", "encapsulate", "decapsulate", "key_sizes"]
        for k in required:
            assert k in result, f"Missing: {k}"

    def test_benchmark_stats_keys(self):
        kem = KyberKEM(KYBER_512)
        result = kem.benchmark(iterations=3)
        for op in ["keygen", "encapsulate", "decapsulate"]:
            assert "mean_ms" in result[op]
            assert "std_ms" in result[op]
            assert "min_ms" in result[op]
            assert "max_ms" in result[op]

    def test_benchmark_times_positive(self):
        kem = KyberKEM(KYBER_512)
        result = kem.benchmark(iterations=3)
        for op in ["keygen", "encapsulate", "decapsulate"]:
            assert result[op]["mean_ms"] > 0

    def test_benchmark_variant_name(self):
        kem = KyberKEM(KYBER_768)
        result = kem.benchmark(iterations=2)
        assert result["variant"] == "Kyber-768"
