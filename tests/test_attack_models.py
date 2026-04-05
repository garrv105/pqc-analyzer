"""
Tests: GroverAttackModel, ShorAttackModel, LatticeAttackModel
"""

import math

import pytest

from pqc_analyzer.quantum.attack_simulator import (
    GroverAttackModel,
    LatticeAttackModel,
    QuantumCircuitDemo,
    ShorAttackModel,
)


class TestGroverAttackModel:
    def setup_method(self):
        self.model = GroverAttackModel()

    def test_required_keys(self):
        result = self.model.analyze(256, "AES")
        required = [
            "algorithm",
            "key_bits",
            "attack",
            "classical_operations",
            "quantum_operations",
            "effective_security_bits",
            "required_qubits",
            "security_label",
            "recommendation",
        ]
        for k in required:
            assert k in result, f"Missing key: {k}"

    def test_aes256_is_secure(self):
        result = self.model.analyze(256, "AES-256")
        assert "SECURE" in result["security_label"]
        assert result["effective_security_bits"] == 128

    def test_aes128_is_broken(self):
        result = self.model.analyze(128, "AES-128")
        assert result["effective_security_bits"] == 64
        assert "BROKEN" in result["security_label"] or "MARGINAL" in result["security_label"]

    def test_quantum_bits_half_of_classical(self):
        for key_bits in [64, 128, 192, 256]:
            result = self.model.analyze(key_bits)
            assert result["effective_security_bits"] == key_bits / 2

    def test_speedup_factor_contains_quadratic(self):
        result = self.model.analyze(128)
        assert "quadratic" in result["speedup_factor"].lower() or "2^" in result["speedup_factor"]

    def test_grover_iterations_positive(self):
        result = self.model.analyze(128)
        assert result["grover_iterations"] > 0

    @pytest.mark.parametrize("key_bits", [64, 128, 192, 256, 512])
    def test_no_crash_on_various_key_sizes(self, key_bits):
        result = self.model.analyze(key_bits)
        assert result["key_bits"] == key_bits


class TestShorAttackModel:
    def setup_method(self):
        self.model = ShorAttackModel()

    def test_rsa_analysis_required_keys(self):
        result = self.model.analyze_rsa(2048)
        required = ["target", "attack", "logical_qubits", "physical_qubits_estimate", "recommendation", "broken"]
        for k in required:
            assert k in result, f"Missing key: {k}"

    def test_rsa_always_broken(self):
        for bits in [512, 1024, 2048, 4096]:
            result = self.model.analyze_rsa(bits)
            assert result["broken"] is True

    def test_larger_rsa_needs_more_qubits(self):
        r2048 = self.model.analyze_rsa(2048)
        r4096 = self.model.analyze_rsa(4096)
        assert r4096["logical_qubits"] > r2048["logical_qubits"]

    def test_physical_qubits_much_larger_than_logical(self):
        result = self.model.analyze_rsa(2048)
        assert result["physical_qubits_estimate"] > result["logical_qubits"] * 10

    def test_ecdlp_analysis_required_keys(self):
        result = self.model.analyze_ecdlp(256)
        required = ["target", "attack", "logical_qubits", "physical_qubits_estimate", "broken"]
        for k in required:
            assert k in result

    def test_ecdlp_always_broken(self):
        for bits in [256, 384, 521]:
            result = self.model.analyze_ecdlp(bits)
            assert result["broken"] is True

    def test_recommendation_mentions_pqc(self):
        result = self.model.analyze_rsa(2048)
        assert "Kyber" in result["recommendation"] or "PQC" in result["recommendation"]


class TestLatticeAttackModel:
    def setup_method(self):
        self.model = LatticeAttackModel()

    def test_known_variants_exist(self):
        for variant in ["Kyber-512", "Kyber-768", "Kyber-1024"]:
            result = self.model.analyze(variant)
            assert "error" not in result

    def test_kyber512_security_bits(self):
        result = self.model.analyze("Kyber-512")
        assert result["classical_security_bits"] == 118
        assert result["quantum_security_bits"] == 107

    def test_kyber768_security_bits(self):
        result = self.model.analyze("Kyber-768")
        assert result["classical_security_bits"] == 183
        assert result["quantum_security_bits"] == 170

    def test_kyber1024_security_bits(self):
        result = self.model.analyze("Kyber-1024")
        assert result["classical_security_bits"] == 257
        assert result["quantum_security_bits"] == 240

    def test_all_kyber_secure(self):
        for variant in ["Kyber-512", "Kyber-768", "Kyber-1024"]:
            result = self.model.analyze(variant)
            assert result["status"] == "SECURE"

    def test_higher_k_more_secure(self):
        r512 = self.model.analyze("Kyber-512")
        r768 = self.model.analyze("Kyber-768")
        r1024 = self.model.analyze("Kyber-1024")
        assert r1024["quantum_security_bits"] > r768["quantum_security_bits"] > r512["quantum_security_bits"]

    def test_unknown_variant_returns_error(self):
        result = self.model.analyze("Kyber-9999")
        assert "error" in result

    def test_nist_categories(self):
        assert self.model.analyze("Kyber-512")["nist_category"] == 1
        assert self.model.analyze("Kyber-768")["nist_category"] == 3
        assert self.model.analyze("Kyber-1024")["nist_category"] == 5

    def test_compare_all_returns_list(self):
        results = self.model.compare_all()
        assert len(results) == 3

    def test_bkz_blocksize_positive(self):
        for variant in ["Kyber-512", "Kyber-768", "Kyber-1024"]:
            r = self.model.analyze(variant)
            assert r["bkz_blocksize_classical"] > 0
            assert r["bkz_blocksize_quantum"] > 0

    def test_classical_security_gt_quantum(self):
        for variant in ["Kyber-512", "Kyber-768", "Kyber-1024"]:
            r = self.model.analyze(variant)
            assert r["classical_security_bits"] > r["quantum_security_bits"]


class TestQuantumCircuitDemo:
    def setup_method(self):
        self.demo = QuantumCircuitDemo()

    def test_grover_demo_runs(self):
        result = self.demo.grover_2qubit_demo("11")
        assert "type" in result
        assert "qubits" in result
        assert result["qubits"] == 2

    @pytest.mark.parametrize("target", ["00", "01", "10", "11"])
    def test_grover_all_targets(self, target):
        result = self.demo.grover_2qubit_demo(target)
        assert result["target_state"] == target

    def test_grover_speedup_mentioned(self):
        result = self.demo.grover_2qubit_demo("10")
        speedup = result.get("speedup", result.get("speedup_factor", ""))
        assert len(speedup) > 0
