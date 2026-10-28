# Threat Model — megaminer

> **Baseline**: Post-Cuartel audit (Scotynau Gatekeeper + Elijas Chaos + Grox666 Exhumador + Nada Minimalista)
> **Fecha**: 2026-10-28
> **Versión**: 1.0

---

## 1. Actores de Amenaza

| ID | Actor | Capacidad | Motivación | Origen |
|----|-------|-----------|------------|--------|
| **A1** | **Pool MITM** | Intercepta/modifica tráfico Stratum (TCP plano o TLS sin pinning) | Robo de hashrate, redirección a pool malicioso, manipulación de trabajos | Red local (ARP spoof), ISP, BGP hijack, Wi-Fi comprometido |
| **A2** | **API Attacker (LAN/WAN)** | Acceso a puerto API (HTTP/WS/SSE), fuzzing, brute-force, DoS | Toma de control del miner, exfiltración de config, denial of service | Red expuesta, config por defecto insegura, credenciales débiles |
| **A3** | **GPU Driver Exploit** | Kernel CUDA malicioso, NVML/NVAPI DLL hijack, race conditions en driver | Escalada de privilegios (kernel), brick GPU, exfiltración memoria VRAM | Supply chain driver, CUDA kernel JIT, DLL search order |
| **A4** | **Supply Chain (Deps)** | vcpkg compromise, transitive dep malicious code, CI/CD poison | Backdoor en binario, crypto-miner oculto, data exfil | Compromiso upstream, typosquatting, maintainer account takeover |
| **A5** | **Insider (Config Leak)** | Acceso a `pools.conf`, API keys, TLS certs, env vars | Robo de credenciales pool, wallet addresses, lateral movement | Backup expuesto, logs, shared configs, repos públicos |

---

## 2. Superficies de Ataque

| Superficie | Protocolo/Interfaz | Vectores Pre-Cuartel | Estado Post-Cuartel |
|------------|-------------------|---------------------|---------------------|
| **Stratum** | TCP (3333), TLS (3334) | Plaintext, sin cert validation, MITM trivial | **TLS obligatorio + cert pinning** (`stratum+tl://`, `--pool-cert-pin`) |
| **API** | HTTP/WS/SSE (puerto 4028 default) | Bind 0.0.0.0, Basic Auth, WS SHA-1, sin rate limit | **TLS obligatorio + bind 127.0.0.1 default + rate limit + SSE (no WS SHA-1)** |
| **RPC** | JSON-RPC sobre HTTP/WS | Sin auth, batch requests unbounded | Hereda controles API (TLS, rate limit, bind local) |
| **GPU Kernels** | CUDA (JIT PTX/SASS) | Kernel sin validación, buffer overflow VRAM | **Build hardening** (ver §3), sin sandbox kernel (residual) |
| **NVML/NVAPI** | DLL load (`nvml.dll`, `nvapi64.dll`) | `LoadLibrary` sin flags, DLL hijack | **DLL safe loading** (`LOAD_LIBRARY_SEARCH_SYSTEM32`) |
| **Config Files** | `pools.conf`, `config.json`, env | Plaintext, world-readable, secretos en repo | **Documentado en Hardening Guide** (permisos, vault) |

---

## 3. Controles Implementados (Post-Cuartel)

### 3.1 Stratum — TLS + Certificate Pinning
- **Protocolo**: `stratum+tl://pool.example.com:3334`
- **Flag**: `--pool-cert-pin <sha256-fingerprint>`
- **Implementación**: Validación de certificado contra fingerprint SHA-256 hardcodeado/configurable
- **Cobertura**: Previene MITM incluso con CA comprometida

### 3.2 API — Hardening Completo
| Control | Implementación |
|---------|----------------|
| TLS obligatorio | `--api-tls-cert` + `--api-tls-key` requeridos si `--api-bind` != 127.0.0.1 |
| Bind por defecto | `127.0.0.1:4028` (solo loopback) |
| Rate limiting | Token bucket: 100 req/s burst 200, por IP |
| Transporte | **SSE only** — WebSocket removido (SHA-1 deprecado) |
| Auth | Basic Auth (transicional) — **mTLS pendiente** |

### 3.3 Build Hardening (MSVC / VS2026)
```
/guard:cf          ; Control Flow Guard
/sdl               ; Security Development Lifecycle checks
/permissive-       ; Standards conformance estricto
/CETCOMPAT         ; Intel CET (shadow stacks, IBT)
/GS                ; Buffer security check (stack cookies)
/DYNAMICBASE       ; ASLR (default ON)
/NXCOMPAT          ; DEP/NX (default ON)
/HIGHENTROPYVA     ; 64-bit ASLR entropy
```
- **vcpkg**: Pinned commit + baseline fijo (`vcpkg.json` + `vcpkg-configuration.json`)
- **CUDA**: 13.4 toolkit fijado, `--ptxas-options=-v` para detectar register pressure

### 3.4 Supply Chain
- **vcpkg pinned**: Commit hash en `vcpkg-configuration.json` (`builtin-baseline`)
- **No deps dinámicas runtime**: Todos los deps vinculados estáticamente salvo CUDA/NVML runtime
- **SBOM**: Generado en CI (`cyclonedx-bom`)

### 3.5 DLL Safe Loading
```cpp
// NVML / NVAPI load
HMODULE h = LoadLibraryExW(L"nvml.dll", NULL,
    LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
```
- Elimina DLL search order hijacking (CVE-2025-XXXX class)

### 3.6 Resilience Patterns
- **Circuit Breaker**: API + Stratum (3 fallos → open 30s → half-open)
- **Health/Metrics**: `/healthz` (liveness), `/ready` (readiness), `/metrics` (Prometheus)
- **NVML Retry + State Verify**: Exponential backoff (1s, 2s, 4s, max 30s) + verificación estado GPU post-retry

---

## 4. Riesgo Residual (Accepted / Tracked)

| ID | Riesgo | Impacto | Probabilidad | Mitigación Parcial | Owner | Target |
|----|--------|---------|--------------|-------------------|-------|--------|
| **R1** | **Stratum plaintext (legacy pools)** | Alto (MITM total) | Media | Documentar `--pool-cert-pin` obligatorio; deprecation warning | Scotynau | v2.1 |
| **R2** | **API Basic Auth (no mTLS)** | Medio (cred sniffing) | Alta | mTLS en roadmap; rate limit + bind 127.0.0.1 mitiga LAN | Elijas | v2.0 |
| **R3** | **GPU kernel exploits (sin sandbox)** | Crítico (kernel exploit → RCE) | Baja | Build hardening + driver updates; sandbox CUDA (WDDM 3.0+) en investigación | Grox666 | v3.0 |
| **R4** | **Config secrets en disco** | Medio | Media | Hardening Guide: permisos 600, vault ref, env vars | Nada | v2.0 |
| **R5** | **Supply chain transitive** | Crítico | Baja | vcpkg pinned + SBOM + `cargo audit` equivalent en CI | Scotynau | Continuous |

---

## 5. Matriz de Cobertura (STRIDE)

| Superficie | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|------------|----------|-----------|-------------|-----------------|-----|-----------|
| Stratum TLS+pin | ✅ | ✅ | ⚠️ (no non-rep) | ✅ | ⚠️ (circuit breaker) | ✅ |
| API TLS+rate | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ (Basic Auth) |
| RPC (JSON) | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ |
| GPU Kernels | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ❌ (R3) |
| NVML/NVAPI | ✅ (DLL safe) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Config Files | ⚠️ (perms) | ⚠️ | ✅ | ⚠️ | ✅ | ✅ |

**Leyenda**: ✅ Controlado | ⚠️ Parcial / Residual | ❌ No mitigado

---

## 6. Referencias y Evidencia

- **Auditoría Scotynau**: `audit/scوتنا_network_audit.md` (red, TLS, cert pinning)
- **Auditoría Elijas**: `audit/elijas_chaos_report.md` (fault injection, circuit breaker, rate limit)
- **Exhumación Grox666**: `audit/grox666_forensic.md` (DLL loading, build flags, supply chain)
- **Minimalismo Nada**: `audit/nada_reduction.md` (código removido, superficie reducida ~30%)
- **CI Pipeline**: `.github/workflows/ci.yml` (build flags, vcpkg pinned, SBOM)

---

## 7. Próximos Pasos (Roadmap)

1. **v2.0**: mTLS para API (cert client + CA privada), deprecate Basic Auth
2. **v2.1**: Stratum plaintext hard-fail (reject non-TLS pools por defecto)
3. **v3.0**: GPU kernel sandbox (WDDM 3.0 / CUDA 13.5+ MPS isolation), formal verification kernels críticos
4. **Continuous**: SBOM signing (sigstore), reproducible builds, attestation SLSA Level 3

---

> **"Hope is not a strategy."** — Elijas (Chaos Engineer)
> **"El contexto es todo. El Chesterton's Fence existe por algo."** — Grox666 (Exhumador)
> **"La mejor línea de código es la que NO EXISTE."** — Nada (Minimalista)
> **"Tolerancia cero a la mediocridad."** — Scotynau (Gatekeeper)