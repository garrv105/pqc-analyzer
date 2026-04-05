"""
PQC Analyzer - Quantum Attack Simulator
=========================================
Simulates quantum algorithm behavior and models their impact
on classical and post-quantum cryptographic schemes.

Implemented models:
1. Grover's Algorithm  — quadratic speedup for unstructured search
2. Shor's Algorithm    — polynomial-time factoring and DLOG
3. BKZ Lattice Sieve  — best classical/quantum attack on Kyber

Uses Qiskit for actual quantum circuit simulation (small-scale demonstrations).
Analytical models for cryptographically relevant key sizes.

IMPORTANT: Real quantum attacks on 2048-bit RSA would require ~4000 logical qubits
(~millions of physical qubits with error correction). This simulator models
the ALGORITHMIC behavior, not physical quantum hardware.
"""

import logging
import math
from typing import Dict, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Analytical quantum attack models
# ---------------------------------------------------------------------------


class GroverAttackModel:
    """
    Models Grover's algorithm: quadratic speedup for brute-force search.

    For a symmetric cipher with n-bit key:
    - Classical: O(2^n) operations
    - Quantum:   O(2^(n/2)) operations (Grover search)

    NIST response: double key lengths (e.g., AES-128 → AES-256 for 128-bit PQ security)
    """

    def analyze(self, key_bits: int, algorithm: str = "AES") -> Dict:
        classical_ops = 2**key_bits
        quantum_ops = 2 ** (key_bits / 2)
        quantum_bits = key_bits / 2

        # Required qubits for Grover's (including oracle + work qubits)
        oracle_qubits = key_bits + 10  # rough estimate
        grover_iterations = math.floor(math.pi / 4 * math.sqrt(2**key_bits))

        # Time estimates (assuming 1 million quantum gates/second — optimistic)
        gate_rate = 1e6
        quantum_time_seconds = quantum_ops / gate_rate

        # Security assessment
        if quantum_bits >= 128:
            security_label = "SECURE (post-quantum)"
            recommendation = "Meets post-quantum security requirements"
        elif quantum_bits >= 80:
            security_label = "MARGINAL"
            recommendation = f"Consider upgrading to {key_bits * 2}-bit key"
        else:
            security_label = "BROKEN"
            recommendation = f"Immediately upgrade to {key_bits * 2}-bit key"

        return {
            "algorithm": algorithm,
            "key_bits": key_bits,
            "attack": "Grover's Algorithm",
            "classical_operations": f"2^{key_bits} ≈ {classical_ops:.2e}",
            "quantum_operations": f"2^{key_bits/2:.0f} ≈ {quantum_ops:.2e}",
            "effective_security_bits": quantum_bits,
            "required_qubits": oracle_qubits,
            "grover_iterations": grover_iterations,
            "estimated_quantum_time": f"{quantum_time_seconds:.2e} seconds (1M gates/sec assumption)",
            "security_label": security_label,
            "recommendation": recommendation,
            "speedup_factor": f"2^{key_bits/2:.0f} (quadratic)",
        }


class ShorAttackModel:
    """
    Models Shor's algorithm: polynomial-time factoring of RSA and ECDLP.

    RSA-n: Requires O(n^3) quantum operations, ~2n logical qubits.
    ECC-n: Similar but on elliptic curve group.

    Physical qubit estimates assume surface code error correction
    at ~1% physical error rate → ~1000 physical qubits per logical qubit.
    """

    # Estimated logical qubits for factoring (from research literature)
    LOGICAL_QUBITS = {
        512: 1282,
        1024: 2050,
        2048: 4098,
        3072: 6146,
        4096: 8194,
    }

    GATE_COUNTS = {  # approximate T-gate count (dominant cost)
        512: 1.6e9,
        1024: 1.3e10,
        2048: 1.0e11,
        4096: 8.0e11,
    }

    def analyze_rsa(self, key_bits: int) -> Dict:
        """Analyze Shor's attack complexity on RSA-n."""
        # Find nearest precomputed value
        nearest = min(self.LOGICAL_QUBITS.keys(), key=lambda x: abs(x - key_bits))

        logical_qubits = self.LOGICAL_QUBITS.get(nearest, int(2 * key_bits + 2))
        physical_qubits = logical_qubits * 1000  # surface code overhead

        gate_count = self.GATE_COUNTS.get(nearest, (key_bits**3) * 100)

        # Time at 1 MHz gate rate with error correction
        time_seconds = gate_count / 1e6

        return {
            "target": f"RSA-{key_bits}",
            "attack": "Shor's Algorithm (Factoring)",
            "complexity": f"O(n³ log n log log n) where n={key_bits}",
            "logical_qubits": logical_qubits,
            "physical_qubits_estimate": physical_qubits,
            "approximate_t_gates": f"{gate_count:.2e}",
            "estimated_time_1MHz": f"{time_seconds:.2e} seconds",
            "estimated_time_1GHz": f"{time_seconds/1000:.2e} seconds (speculative)",
            "current_largest_factored": "RSA-829 (2020, classical)",
            "quantum_ready_estimate": "2030-2035 (optimistic) per NIST",
            "recommendation": f"Migrate from RSA-{key_bits} to a PQC KEM (e.g., Kyber-768)",
            "broken": True,
        }

    def analyze_ecdlp(self, curve_bits: int) -> Dict:
        """Analyze Shor's attack on Elliptic Curve Discrete Log."""
        # ECDLP requires ~2.5n qubits for n-bit curve
        logical_qubits = int(2.5 * curve_bits)
        physical_qubits = logical_qubits * 1000
        gate_count = 40 * curve_bits**3

        return {
            "target": f"ECDLP-{curve_bits} ({self._curve_name(curve_bits)})",
            "attack": "Shor's Algorithm (ECDLP variant)",
            "complexity": f"O(n³) where n={curve_bits}",
            "logical_qubits": logical_qubits,
            "physical_qubits_estimate": physical_qubits,
            "approximate_gates": f"{gate_count:.2e}",
            "recommendation": f"Migrate from ECC-{curve_bits} to PQC (Kyber/Dilithium)",
            "broken": True,
        }

    @staticmethod
    def _curve_name(bits: int) -> str:
        return {256: "P-256/secp256k1", 384: "P-384", 521: "P-521", 25519: "X25519"}.get(bits, f"{bits}-bit")


class LatticeAttackModel:
    """
    Models lattice-based attacks (BKZ algorithm) on MLWE/Kyber.

    The best known attacks on Kyber use the BKZ lattice reduction algorithm.
    Security is measured in bits as -log2(probability) of attack success.

    BKZ complexity grows super-exponentially with block size β,
    providing strong security guarantees for well-chosen parameters.

    Reference: Albrecht et al. "On the concrete hardness of Learning with Errors"
    """

    # Security estimates from CRYSTALS-Kyber specification (Table 1)
    KYBER_SECURITY = {
        "Kyber-512": {"classical": 118, "quantum": 107, "nist_category": 1},
        "Kyber-768": {"classical": 183, "quantum": 170, "nist_category": 3},
        "Kyber-1024": {"classical": 257, "quantum": 240, "nist_category": 5},
    }

    def analyze(self, variant: str) -> Dict:
        """Analyze BKZ attack complexity on a Kyber variant."""
        sec = self.KYBER_SECURITY.get(variant)
        if not sec:
            return {"error": f"Unknown variant: {variant}"}

        classical_bits = sec["classical"]
        quantum_bits = sec["quantum"]
        nist_cat = sec["nist_category"]

        # BKZ block size for attack
        # Security ≈ 0.265 * beta * log2(beta) bits (heuristic)
        beta_classical = self._solve_beta(classical_bits)
        beta_quantum = self._solve_beta(quantum_bits)

        nist_targets = {1: 128, 3: 192, 5: 256}
        target = nist_targets[nist_cat]

        return {
            "variant": variant,
            "attack": "BKZ Lattice Reduction",
            "classical_security_bits": classical_bits,
            "quantum_security_bits": quantum_bits,
            "nist_category": nist_cat,
            "target_security_bits": target,
            "security_margin_classical": classical_bits - target,
            "security_margin_quantum": quantum_bits - target,
            "bkz_blocksize_classical": beta_classical,
            "bkz_blocksize_quantum": beta_quantum,
            "status": "SECURE" if quantum_bits >= target - 30 else "INSECURE",
            "notes": (
                "Security holds under MLWE hardness assumption. "
                "No polynomial-time quantum algorithm known for lattice problems. "
                "Grover's speedup provides only quadratic advantage here."
            ),
        }

    def compare_all(self) -> List[Dict]:
        return [self.analyze(v) for v in self.KYBER_SECURITY]

    @staticmethod
    def _solve_beta(target_bits: float) -> int:
        """Numerically solve 0.265 * beta * log2(beta) = target_bits."""
        for beta in range(2, 1000):
            if 0.265 * beta * math.log2(max(beta, 2)) >= target_bits:
                return beta
        return 999


# ---------------------------------------------------------------------------
# Qiskit quantum circuit demonstrations
# ---------------------------------------------------------------------------


class QuantumCircuitDemo:
    """
    Demonstrates real quantum circuits using Qiskit.
    Uses small instances to show quantum behavior:
    - Grover's search (2-3 qubits)
    - Quantum Fourier Transform (key component of Shor's)
    - Period finding (core of Shor's factoring)
    """

    def __init__(self):
        self._qiskit_available = False
        try:
            import qiskit

            self._qiskit_available = True
            logger.info("Qiskit available: %s", qiskit.__version__)
        except ImportError:
            logger.warning("Qiskit not installed. Circuit demos unavailable.")

    def grover_2qubit_demo(self, target_state: str = "11") -> Dict:
        """
        Grover's algorithm on 2 qubits.
        Searches for |target_state⟩ among 4 equally likely states.
        Success probability after 1 iteration: ~1.0 (optimal for n=2).
        """
        if not self._qiskit_available:
            return self._mock_grover(target_state)

        from qiskit import QuantumCircuit, transpile
        from qiskit_aer import AerSimulator

        n_qubits = len(target_state)
        qc = QuantumCircuit(n_qubits, n_qubits)

        # Hadamard for uniform superposition
        qc.h(range(n_qubits))
        qc.barrier()

        # Oracle: phase-flip the target state
        if target_state[0] == "0":
            qc.x(0)
        if target_state[1] == "0":
            qc.x(1)
        qc.cz(0, 1)
        if target_state[0] == "0":
            qc.x(0)
        if target_state[1] == "0":
            qc.x(1)
        qc.barrier()

        # Diffusion operator
        qc.h(range(n_qubits))
        qc.x(range(n_qubits))
        qc.h(1)
        qc.cx(0, 1)
        qc.h(1)
        qc.x(range(n_qubits))
        qc.h(range(n_qubits))
        qc.barrier()

        qc.measure(range(n_qubits), range(n_qubits))

        # Simulate
        try:
            simulator = AerSimulator()
            compiled = transpile(qc, simulator)
            result = simulator.run(compiled, shots=1024).result()
            counts = result.get_counts()
            total = sum(counts.values())
            probabilities = {k: v / total for k, v in counts.items()}
            target_prob = probabilities.get(target_state[::-1], 0)  # qiskit reverses bit order

            return {
                "type": "Grover's Search",
                "qubits": n_qubits,
                "target_state": target_state,
                "search_space": 2**n_qubits,
                "iterations": 1,
                "measurement_counts": counts,
                "target_probability": round(target_prob, 4),
                "speedup": "Quadratic over classical (searches √N states vs N)",
                "circuit_depth": qc.depth(),
                "gate_count": qc.count_ops(),
                "circuit_diagram": str(qc.draw()),
            }
        except Exception as e:
            return self._mock_grover(target_state, error=str(e))

    def qft_demo(self, n_qubits: int = 4) -> Dict:
        """
        Quantum Fourier Transform circuit (core of Shor's period finding).
        """
        if not self._qiskit_available:
            return {"type": "QFT", "error": "Qiskit not available", "qubits": n_qubits}

        import math

        from qiskit import QuantumCircuit

        qc = QuantumCircuit(n_qubits)

        def qft_rotations(circuit, n):
            if n == 0:
                return circuit
            n -= 1
            circuit.h(n)
            for qubit in range(n):
                circuit.cp(math.pi / 2 ** (n - qubit), qubit, n)
            qft_rotations(circuit, n)

        def swap_registers(circuit, n):
            for qubit in range(n // 2):
                circuit.swap(qubit, n - qubit - 1)

        qft_rotations(qc, n_qubits)
        swap_registers(qc, n_qubits)

        return {
            "type": "Quantum Fourier Transform",
            "qubits": n_qubits,
            "gate_count": qc.count_ops(),
            "circuit_depth": qc.depth(),
            "role_in_shor": "QFT is used in Shor's algorithm to extract the period of f(x) = a^x mod N",
            "classical_dft_complexity": f"O(N log N) for {2**n_qubits} points",
            "quantum_qft_complexity": f"O(n²) = O({n_qubits**2}) for {n_qubits} qubits",
            "circuit_diagram": str(qc.draw()),
        }

    def _mock_grover(self, target: str, error: str = None) -> Dict:
        """Return analytical Grover results when Qiskit is unavailable."""
        n = len(target)
        N = 2**n
        return {
            "type": "Grover's Search (analytical model)",
            "qubits": n,
            "target_state": target,
            "search_space": N,
            "iterations": 1,
            "target_probability_theoretical": (
                round(1 - 1 / N, 4) if n == 2 else round(math.sin((2 * 1 + 1) * math.asin(1 / math.sqrt(N))) ** 2, 4)
            ),
            "note": f"Qiskit simulation unavailable{': ' + error if error else ''}. Showing analytical results.",
            "speedup": "Quadratic: finds solution in O(√N) vs O(N) classically",
        }
