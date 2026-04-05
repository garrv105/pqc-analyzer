"""
Tests: SecurityStrengthPredictor, ParameterOptimizer, WeaknessDetector
"""

import pytest

from pqc_analyzer.ai.optimizer import ParameterOptimizer, SecurityStrengthPredictor, WeaknessDetector


class TestSecurityStrengthPredictor:
    def setup_method(self):
        self.predictor = SecurityStrengthPredictor()

    def test_predict_returns_required_keys(self):
        result = self.predictor.predict(3, 256, 3329, 2, 10, 4, 1184, 1088)
        required = [
            "predicted_classical_security_bits",
            "predicted_quantum_security_bits",
            "nist_category",
            "is_weak_configuration",
            "recommendation",
        ]
        for k in required:
            assert k in result

    def test_kyber768_predicted_secure(self):
        result = self.predictor.predict(3, 256, 3329, 2, 10, 4, 1184, 1088)
        assert not result["is_weak_configuration"]
        assert result["predicted_quantum_security_bits"] > 100

    def test_weak_params_flagged(self):
        result = self.predictor.predict(1, 256, 769, 5, 8, 4, 300, 250)
        assert result["is_weak_configuration"]

    def test_prediction_values_positive(self):
        result = self.predictor.predict(2, 256, 3329, 3, 10, 4, 800, 768)
        assert result["predicted_classical_security_bits"] > 0
        assert result["predicted_quantum_security_bits"] > 0

    def test_higher_k_predicts_higher_security(self):
        r_k2 = self.predictor.predict(2, 256, 3329, 2, 10, 4, 800, 768)
        r_k4 = self.predictor.predict(4, 256, 3329, 2, 11, 5, 1568, 1568)
        assert r_k4["predicted_quantum_security_bits"] > r_k2["predicted_quantum_security_bits"]

    def test_nist_category_valid(self):
        result = self.predictor.predict(3, 256, 3329, 2, 10, 4, 1184, 1088)
        assert result["nist_category"] in [0, 1, 3, 5]

    def test_feature_importance_returns_list(self):
        importance = self.predictor.get_feature_importance()
        assert isinstance(importance, list)
        assert len(importance) > 0
        assert "feature" in importance[0]
        assert "importance" in importance[0]

    def test_importance_sums_to_one(self):
        importance = self.predictor.get_feature_importance()
        total = sum(f["importance"] for f in importance)
        assert abs(total - 1.0) < 1e-5


class TestParameterOptimizer:
    def setup_method(self):
        self.predictor = SecurityStrengthPredictor()
        self.optimizer = ParameterOptimizer(self.predictor)

    def test_optimize_returns_required_keys(self):
        result = self.optimizer.optimize(target_quantum_bits=100, n_trials=50)
        required = ["target_quantum_bits", "trials", "valid_configs_found", "top_5_configurations"]
        for k in required:
            assert k in result

    def test_found_configs_meet_target(self):
        target = 100
        result = self.optimizer.optimize(target_quantum_bits=target, n_trials=100)
        for cfg in result["top_5_configurations"]:
            assert cfg["predicted_quantum_bits"] >= target

    def test_configs_respect_size_constraints(self):
        max_pk = 900
        max_ct = 900
        result = self.optimizer.optimize(target_quantum_bits=80, max_pk_bytes=max_pk, max_ct_bytes=max_ct, n_trials=200)
        for cfg in result["top_5_configurations"]:
            assert cfg["pk_bytes"] <= max_pk
            assert cfg["ct_bytes"] <= max_ct

    def test_efficiency_score_positive(self):
        result = self.optimizer.optimize(target_quantum_bits=100, n_trials=100)
        for cfg in result["top_5_configurations"]:
            assert cfg["efficiency_score"] > 0

    def test_configs_sorted_by_efficiency(self):
        result = self.optimizer.optimize(target_quantum_bits=80, n_trials=200)
        scores = [c["efficiency_score"] for c in result["top_5_configurations"]]
        assert scores == sorted(scores, reverse=True)


class TestWeaknessDetector:
    def setup_method(self):
        self.detector = WeaknessDetector()

    def test_kyber768_is_safe(self):
        result = self.detector.check(3, 256, 3329, 2, 10, 4)
        assert result["overall_assessment"] == "SAFE"
        assert len(result["critical_issues"]) == 0

    def test_small_q_flagged(self):
        result = self.detector.check(2, 256, 500, 2, 10, 4)
        assert result["overall_assessment"] == "UNSAFE"
        assert len(result["critical_issues"]) > 0

    def test_small_n_flagged(self):
        result = self.detector.check(2, 64, 3329, 2, 10, 4)
        assert result["overall_assessment"] == "UNSAFE"

    def test_large_eta_flagged(self):
        result = self.detector.check(2, 256, 3329, 7, 10, 4)
        assert result["overall_assessment"] == "UNSAFE"

    def test_small_k_warns(self):
        result = self.detector.check(1, 256, 3329, 2, 10, 4)
        assert result["overall_assessment"] in ["CAUTION", "UNSAFE"]

    def test_result_contains_config(self):
        result = self.detector.check(3, 256, 3329, 2, 10, 4)
        assert "configuration" in result
        assert result["configuration"]["k"] == 3
        assert result["configuration"]["q"] == 3329

    def test_warnings_is_list(self):
        result = self.detector.check(3, 256, 3329, 2, 10, 4)
        assert isinstance(result["warnings"], list)
        assert isinstance(result["critical_issues"], list)
