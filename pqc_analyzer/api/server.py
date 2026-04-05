"""
PQC Analyzer - REST API Server
================================
FastAPI server providing:
- POST /auth/token               — obtain JWT access token
- GET  /api/v1/health            — unauthenticated health probe
- POST /api/v1/analyze/kyber     — benchmark and analyze Kyber variant
- POST /api/v1/analyze/classical — benchmark classical algorithm
- POST /api/v1/attack/grover     — model Grover's attack on symmetric key
- POST /api/v1/attack/shor       — model Shor's attack on RSA/ECC
- POST /api/v1/attack/lattice    — model BKZ attack on Kyber
- POST /api/v1/optimize          — AI-optimized parameter search
- POST /api/v1/check-weakness    — validate parameter set for weaknesses
- POST /api/v1/quantum/demo      — run Qiskit quantum circuit demo
- GET  /api/v1/compare           — full comparative analysis
- GET  /api/v1/charts/*          — serve generated charts

Security hardening:
- JWT Bearer token authentication (HS256)
- API Key header authentication (fallback)
- Rate limiting via slowapi (per-IP)
- Security headers middleware
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import CurrentUser, TokenResponse, get_current_user, login_for_access_token

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
_ALLOWED_ORIGINS = os.getenv("PQC_CORS_ORIGINS", "*")


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return response


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class KyberAnalysisRequest(BaseModel):
    variant: str = Field("Kyber-768", pattern="^Kyber-(512|768|1024)$")
    iterations: int = Field(50, ge=10, le=500)


class ClassicalAnalysisRequest(BaseModel):
    algorithm: str = Field("RSA-2048", description="RSA-2048, RSA-4096, ECDH-X25519, ECDH-P256")
    iterations: int = Field(20, ge=5, le=200)


class GroverRequest(BaseModel):
    key_bits: int = Field(256, ge=64, le=512)
    algorithm: str = Field("AES")


class ShorRequest(BaseModel):
    target: str = Field("RSA-2048", description="RSA-2048, RSA-4096, ECDH-P256, ECDH-P384")


class LatticeAttackRequest(BaseModel):
    variant: str = Field("Kyber-768", pattern="^Kyber-(512|768|1024)$")


class OptimizeRequest(BaseModel):
    target_quantum_bits: int = Field(128, ge=80, le=300)
    max_pk_bytes: int = Field(1200, ge=400, le=3000)
    max_ct_bytes: int = Field(1100, ge=400, le=3000)
    n_trials: int = Field(500, ge=100, le=2000)


class WeaknessRequest(BaseModel):
    k: int = Field(..., ge=1, le=8)
    n: int = Field(256, ge=64, le=512)
    q: int = Field(3329, ge=256)
    eta: int = Field(2, ge=1, le=8)
    du: int = Field(10, ge=4, le=14)
    dv: int = Field(4, ge=2, le=10)


class GroverCircuitRequest(BaseModel):
    target_state: str = Field("11", pattern="^[01]{2}$")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(output_dir: str = "outputs") -> FastAPI:
    app = FastAPI(
        title="PQC Analyzer API",
        description=(
            "Post-Quantum Cryptography Analyzer with AI Optimization — Research Tool.\n\n"
            "**Authentication:** All endpoints (except `/auth/token` and `/api/v1/health`) require:\n"
            "- `Authorization: Bearer <jwt>` — obtain from `POST /auth/token`\n"
            "- `X-API-Key: <key>` — configure via `PQC_API_KEYS` env var\n\n"
            "**Rate limits:** 200 requests/minute per IP; 10/minute on auth endpoints.\n\n"
            "**Default dev credentials:** `admin` / `changeme` (override via env vars in production)."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS.split(",") if _ALLOWED_ORIGINS != "*" else ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Lazy-load expensive components
    _state: dict = {}

    def get_components():
        if "ready" not in _state:
            from ..crypto.kyber import KyberKEM, KYBER_VARIANTS
            from ..crypto.classical import RSABenchmark, ECDHBenchmark
            from ..quantum.attack_simulator import (
                GroverAttackModel,
                ShorAttackModel,
                LatticeAttackModel,
                QuantumCircuitDemo,
            )
            from ..ai.optimizer import SecurityStrengthPredictor, ParameterOptimizer, WeaknessDetector

            _state.update({
                "kyber_variants": KYBER_VARIANTS,
                "grover": GroverAttackModel(),
                "shor": ShorAttackModel(),
                "lattice": LatticeAttackModel(),
                "qc_demo": QuantumCircuitDemo(),
                "predictor": SecurityStrengthPredictor(),
                "weakness": WeaknessDetector(),
                "ready": True,
            })
            _state["optimizer"] = ParameterOptimizer(_state["predictor"])
        return _state

    # -----------------------------------------------------------------------
    # Auth endpoint (public)
    # -----------------------------------------------------------------------

    @app.post(
        "/auth/token",
        response_model=TokenResponse,
        tags=["auth"],
        summary="Obtain a JWT access token",
    )
    @limiter.limit("10/minute")
    async def token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
        """
        Exchange credentials for a JWT access token.

        Default dev credentials: `admin` / `changeme`
        Override via `PQC_ADMIN_USER` and `PQC_ADMIN_PASS_HASH` env vars.
        """
        return await login_for_access_token(form_data)

    # -----------------------------------------------------------------------
    # Health (public)
    # -----------------------------------------------------------------------

    @app.get("/api/v1/health", tags=["system"])
    async def health():
        try:
            import qiskit
            qiskit_available = True
        except ImportError:
            qiskit_available = False
        return {"status": "ok", "version": "1.0.0", "qiskit_available": qiskit_available}

    # -----------------------------------------------------------------------
    # Protected endpoints
    # -----------------------------------------------------------------------

    @app.post("/api/v1/analyze/kyber", tags=["analysis"])
    @limiter.limit("30/minute")
    async def analyze_kyber(
        request: Request,
        req: KyberAnalysisRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Benchmark a Kyber variant and return comprehensive security analysis."""
        from ..crypto.kyber import KyberKEM, KYBER_VARIANTS
        s = get_components()
        params = s["kyber_variants"][req.variant]
        kem = KyberKEM(params)
        bench = kem.benchmark(iterations=req.iterations)
        bench["security_analysis"] = s["lattice"].analyze(req.variant)
        bench["requested_by"] = _user.username
        return bench

    @app.post("/api/v1/analyze/classical", tags=["analysis"])
    @limiter.limit("30/minute")
    async def analyze_classical(
        request: Request,
        req: ClassicalAnalysisRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Benchmark a classical cryptographic algorithm."""
        from ..crypto.classical import RSABenchmark, ECDHBenchmark

        if req.algorithm.startswith("RSA"):
            bits = int(req.algorithm.split("-")[1])
            result = RSABenchmark(bits).benchmark(req.iterations)
        elif req.algorithm.startswith("ECDH"):
            curve = req.algorithm.split("-", 1)[1]
            result = ECDHBenchmark(curve).benchmark(req.iterations)
        else:
            raise HTTPException(400, f"Unknown algorithm: {req.algorithm}")
        return result

    @app.post("/api/v1/attack/grover", tags=["attacks"])
    @limiter.limit("60/minute")
    async def grover_attack(
        request: Request,
        req: GroverRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Model Grover's algorithm attack on a symmetric cipher."""
        s = get_components()
        return s["grover"].analyze(req.key_bits, req.algorithm)

    @app.post("/api/v1/attack/shor", tags=["attacks"])
    @limiter.limit("60/minute")
    async def shor_attack(
        request: Request,
        req: ShorRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Model Shor's algorithm attack on RSA or ECC."""
        s = get_components()
        if "RSA" in req.target:
            bits = int(req.target.split("-")[1])
            return s["shor"].analyze_rsa(bits)
        else:
            curve = req.target.split("-")[-1]
            bits_map = {"P256": 256, "P384": 384, "X25519": 255}
            return s["shor"].analyze_ecdlp(bits_map.get(curve.replace("-", ""), 256))

    @app.post("/api/v1/attack/lattice", tags=["attacks"])
    @limiter.limit("60/minute")
    async def lattice_attack(
        request: Request,
        req: LatticeAttackRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Model BKZ lattice reduction attack on Kyber."""
        s = get_components()
        return s["lattice"].analyze(req.variant)

    @app.post("/api/v1/optimize", tags=["ai"])
    @limiter.limit("10/minute")
    async def optimize_params(
        request: Request,
        req: OptimizeRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """AI-driven Kyber parameter optimization (computationally intensive)."""
        s = get_components()
        return s["optimizer"].optimize(
            target_quantum_bits=req.target_quantum_bits,
            max_pk_bytes=req.max_pk_bytes,
            max_ct_bytes=req.max_ct_bytes,
            n_trials=req.n_trials,
        )

    @app.post("/api/v1/check-weakness", tags=["analysis"])
    @limiter.limit("60/minute")
    async def check_weakness(
        request: Request,
        req: WeaknessRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Validate a Kyber-like parameter set for cryptographic weaknesses."""
        s = get_components()
        check = s["weakness"].check(req.k, req.n, req.q, req.eta, req.du, req.dv)
        prediction = s["predictor"].predict(
            req.k, req.n, req.q, req.eta, req.du, req.dv,
            32 * req.k * req.n * 12 // 8 + 32,
            req.k * req.n * req.du // 8 + req.n * req.dv // 8,
        )
        check["ai_security_prediction"] = prediction
        return check

    @app.post("/api/v1/quantum/grover-circuit", tags=["quantum"])
    @limiter.limit("10/minute")
    async def grover_circuit(
        request: Request,
        req: GroverCircuitRequest,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Run a real Grover's algorithm circuit simulation via Qiskit."""
        s = get_components()
        return s["qc_demo"].grover_2qubit_demo(req.target_state)

    @app.get("/api/v1/compare", tags=["analysis"])
    @limiter.limit("5/minute")
    async def full_comparison(
        request: Request,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Full comparative analysis: all Kyber variants vs classical algorithms."""
        from ..crypto.kyber import KyberKEM, KYBER_VARIANTS
        from ..crypto.classical import RSABenchmark, ECDHBenchmark

        results: dict = {"kyber": {}, "classical": {}}

        for name, params in KYBER_VARIANTS.items():
            try:
                kem = KyberKEM(params)
                results["kyber"][name] = kem.benchmark(iterations=20)
            except Exception as e:
                results["kyber"][name] = {"error": str(e)}

        for alg, cls, args in [
            ("RSA-2048", RSABenchmark, (2048,)),
            ("ECDH-X25519", ECDHBenchmark, ("X25519",)),
        ]:
            try:
                results["classical"][alg] = cls(*args).benchmark(5)
            except Exception as e:
                results["classical"][alg] = {"error": str(e)}

        return results

    @app.get("/api/v1/charts/generate", tags=["charts"])
    @limiter.limit("5/minute")
    async def generate_charts(
        request: Request,
        bg: BackgroundTasks,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Trigger chart generation (runs in background)."""
        from ..visualization.charts import generate_all_charts
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        bg.add_task(generate_all_charts, output_dir=output_dir)
        return {"message": "Chart generation started", "output_dir": output_dir}

    @app.get("/api/v1/charts/{chart_name}", tags=["charts"])
    @limiter.limit("60/minute")
    async def get_chart(
        request: Request,
        chart_name: str,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Serve a generated chart PNG."""
        # Sanitise chart_name to prevent path traversal
        safe_name = Path(chart_name).name
        path = Path(output_dir) / f"{safe_name}.png"
        if not path.exists():
            raise HTTPException(404, f"Chart '{safe_name}' not found. Call /charts/generate first.")
        return FileResponse(str(path), media_type="image/png")

    return app
