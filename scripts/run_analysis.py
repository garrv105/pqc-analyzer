"""
PQC Analyzer - Full Analysis Pipeline
========================================
Runs the complete analysis suite:
1. Benchmark all Kyber variants
2. Benchmark classical algorithms
3. Model quantum attacks
4. Run AI optimization
5. Generate all visualizations
6. Print comprehensive report
"""

import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("pqc_analyzer.run")


def print_banner():
    print("\n" + "=" * 70)
    print("  PQC ANALYZER — Post-Quantum Cryptography Analysis Suite")
    print("  Research-Grade | NIST PQC Standards | AI-Optimized")
    print("=" * 70 + "\n")


def main():
    print_banner()
    output_dir = "outputs"
    Path(output_dir).mkdir(exist_ok=True)

    # -----------------------------------------------
    # 1. Kyber benchmarks
    # -----------------------------------------------
    print("[ 1/5 ] Benchmarking Kyber variants...")
    from pqc_analyzer.crypto.kyber import KYBER_VARIANTS, KyberKEM

    kyber_results = {}
    for name, params in KYBER_VARIANTS.items():
        print(f"       Running {name} (50 iterations)...")
        kem = KyberKEM(params)
        result = kem.benchmark(iterations=50)
        kyber_results[name] = result
        print(
            f"         KeyGen: {result['keygen']['mean_ms']:.4f}ms | "
            f"Encap: {result['encapsulate']['mean_ms']:.4f}ms | "
            f"Decap: {result['decapsulate']['mean_ms']:.4f}ms"
        )
        print(
            f"         PK: {result['key_sizes']['public_key_bytes']}B | "
            f"SK: {result['key_sizes']['private_key_bytes']}B | "
            f"CT: {result['key_sizes']['ciphertext_bytes']}B"
        )

    # -----------------------------------------------
    # 2. Classical benchmarks
    # -----------------------------------------------
    print("\n[ 2/5 ] Benchmarking classical algorithms...")
    classical_results = []

    try:
        from pqc_analyzer.crypto.classical import ECDHBenchmark, RSABenchmark, SymmetricBenchmark

        for alg, cls, args, iters in [
            ("RSA-2048", RSABenchmark, (2048,), 5),
            ("RSA-4096", RSABenchmark, (4096,), 5),
            ("ECDH-X25519", ECDHBenchmark, ("X25519",), 50),
            ("ECDH-P256", ECDHBenchmark, ("P-256",), 50),
        ]:
            print(f"       {alg}...")
            r = cls(*args).benchmark(iters)
            classical_results.append(r)
            print(f"         KeyGen: {r['keygen']['mean_ms']:.2f}ms")

        sym = SymmetricBenchmark().benchmark(iterations=100)
        classical_results.append(sym)
        print(f"       AES-256-GCM: {sym['results_by_size']['1KB']['throughput_mbps']:.1f} MB/s (1KB)")
    except Exception as e:
        print(f"       WARNING: Classical benchmarks failed: {e}")

    # -----------------------------------------------
    # 3. Quantum attack modeling
    # -----------------------------------------------
    print("\n[ 3/5 ] Modeling quantum attacks...")
    from pqc_analyzer.quantum.attack_simulator import (
        GroverAttackModel,
        LatticeAttackModel,
        QuantumCircuitDemo,
        ShorAttackModel,
    )

    grover = GroverAttackModel()
    shor = ShorAttackModel()
    lattice = LatticeAttackModel()

    print("\n  --- Grover's Algorithm Impact on Symmetric Keys ---")
    for bits, alg in [(128, "AES-128"), (256, "AES-256")]:
        r = grover.analyze(bits, alg)
        print(f"  {alg}: Classical={r['classical_operations']} → Quantum={r['quantum_operations']}")
        print(f"         Effective PQ Security: {r['effective_security_bits']} bits | {r['security_label']}")

    print("\n  --- Shor's Algorithm on RSA ---")
    for bits in [2048, 4096]:
        r = shor.analyze_rsa(bits)
        print(
            f"  RSA-{bits}: {r['logical_qubits']} logical qubits | ~{r['physical_qubits_estimate']:,} physical qubits"
        )

    print("\n  --- BKZ Lattice Attack on Kyber ---")
    for analysis in lattice.compare_all():
        v = analysis.get("variant", "?")
        print(
            f"  {v}: Classical={analysis.get('classical_security_bits')}b | "
            f"Quantum={analysis.get('quantum_security_bits')}b | Status={analysis.get('status')}"
        )

    # Quantum circuit demo
    demo = QuantumCircuitDemo()
    grover_demo = demo.grover_2qubit_demo("11")
    print(f"\n  Grover 2-qubit demo (target |11⟩): {grover_demo.get('type', 'N/A')}")

    # -----------------------------------------------
    # 4. AI Optimization
    # -----------------------------------------------
    print("\n[ 4/5 ] Running AI parameter optimization...")
    from pqc_analyzer.ai.optimizer import ParameterOptimizer, SecurityStrengthPredictor, WeaknessDetector

    predictor = SecurityStrengthPredictor()
    optimizer = ParameterOptimizer(predictor)
    weakness = WeaknessDetector()

    print("  Optimizing for 128-bit post-quantum security (max 1200B public key)...")
    opt_result = optimizer.optimize(target_quantum_bits=128, n_trials=300)
    print(f"  Found {opt_result['valid_configs_found']} valid configurations")
    if opt_result.get("most_efficient"):
        best = opt_result["most_efficient"]
        print(
            f"  Most efficient: k={best['k']}, n={best['n']}, q={best['q']}, "
            f"η={best['eta1']}, PQ={best['predicted_quantum_bits']}b, "
            f"PK={best['pk_bytes']}B"
        )

    print("\n  Checking weak parameter configurations...")
    for k, n, q, eta in [(1, 256, 769, 5), (2, 256, 3329, 2)]:
        r = weakness.check(k, n, q, eta, 10, 4)
        print(
            f"  k={k},q={q}: {r['overall_assessment']} | "
            f"Issues: {len(r['critical_issues'])} critical, {len(r['warnings'])} warnings"
        )

    # -----------------------------------------------
    # 5. Visualizations
    # -----------------------------------------------
    print("\n[ 5/5 ] Generating visualizations...")
    try:
        from pqc_analyzer.visualization.charts import generate_all_charts

        all_benchmarks = list(kyber_results.values()) + classical_results
        chart_paths = generate_all_charts(all_benchmarks, output_dir)
        for name, path in chart_paths.items():
            if path:
                print(f"  Saved: {path}")
    except Exception as e:
        print(f"  WARNING: Visualization failed: {e}")

    # -----------------------------------------------
    # Save full results
    # -----------------------------------------------
    results_path = Path(output_dir) / "full_analysis.json"
    with open(results_path, "w") as f:
        json.dump(
            {
                "kyber_benchmarks": kyber_results,
                "optimization": opt_result,
            },
            f,
            indent=2,
            default=str,
        )
    print(f"\n  Full results saved to {results_path}")

    print("\n" + "=" * 70)
    print("  Analysis complete.")
    print(f"  Charts in: {output_dir}/")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
