# Hardening Guide — megaminer

> **Aplicable a**: v2.0+ (post-Cuartel audit)
> **Audiencia**: DevOps, Release Engineers, Security Team
> **Fecha**: 2026-10-28

---

## 1. Build Hardening

### 1.1 Toolchain Requerido
| Componente | Versión Mínima | Notas |
|------------|----------------|-------|
| **Visual Studio** | 2026 17.10+ | `/guard:cf`, `/CETCOMPAT` requieren toolset v144+ |
| **Windows SDK** | 10.0.26100+ | High entropy VA, CET support |
| **CUDA Toolkit** | 13.4 (exact) | Fijado en `vcpkg.json` + `CMakeLists.txt` |
| **vcpkg** | 2026.10.15 (commit pinned) | Baseline: `a1b2c3d4e5f6...` (ver `vcpkg-configuration.json`) |
| **CMake** | 3.30+ | `CMAKE_CXX_FLAGS` hardening propagado |

### 1.2 Flags de Compilación (Obligatorios)

#### MSVC (Release)
```cmake
# CMakeLists.txt — target_compile_options(megaminer PRIVATE ...)
/guard:cf          # Control Flow Guard
/sdl               # Security Development Lifecycle
/permissive-       # Conformance estricto (no extensions)
/CETCOMPAT         # Intel CET: Shadow Stacks + IBT
/GS                # Stack cookies (buffer overrun detection)
/DYNAMICBASE       # ASLR (default ON, explícito)
/NXCOMPAT          # DEP/NX (default ON, explícito)
/HIGHENTROPYVA     # 64-bit ASLR entropy
/GA                # Optimize for Windows Application (speed)
/O2                # Maximum optimization
/GL                # Whole program optimization
/LTCG             # Link-time code generation
```

#### NVCC (CUDA Kernels)
```cmake
# Kernels .cu
-arch=native                    # O sm_90 (Blackwell) / sm_100 (Vera Rubin)
-ptxas-options=-v               # Register pressure visibility
-lineinfo                       # Debug symbols en PTX (perf analysis)
-Xcompiler=/guard:cf            # CFG en host code
-Xcompiler=/GS                  # Stack cookies host
--fmad=false                    # Determinismo FP (auditable)
```

### 1.3 vcpkg Setup (Reproducible + Pinned)
```bash
# Bootstrap (una vez)
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg && ./bootstrap-vcpkg.sh

# Pin commit exacto (en repo megaminer)
cat vcpkg-configuration.json
{
  "default-registry": { "kind": "git", "repository": "https://github.com/microsoft/vcpkg.git", "baseline": "a1b2c3d4e5f67890..." },
  "registries": []
}

# Install (CI y local idénticos)
vcpkg install --triplet x64-windows-static-md
# static-md = static runtime (/MT) — evita DLL hell, reduce superficie
```

### 1.4 Verificación Post-Build
```powershell
# 1. Binario firmado + timestamps
signtool sign /tr http://timestamp.digicert.com /fd sha256 megaminer.exe

# 2. Verificar hardening flags
dumpbin /headers megaminer.exe | findstr "DYNAMICBASE NXCOMPAT HIGHENTROPYVA CETCOMPAT"
# Debe mostrar: DLL can move, NX compatible, High entropy VA, CET compatible

# 3. Control Flow Guard
dumpbin /loadconfig megaminer.exe | findstr "GUARD_CF"
# Debe mostrar: GUARD_CF_FUNCTION_TABLE_PRESENT, GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT

# 4. Dependencias (solo system + CUDA/NVML)
dumpbin /dependents megaminer.exe
# KERNEL32.dll, USER32.dll, nvcuda.dll, nvml.dll, ADVAPI32.dll, WS2_32.dll — NADA MÁS
```

---

## 2. Runtime Hardening

### 2.1 TLS Certificates — Generación

#### CA Privada (para mTLS futuro + API TLS)
```bash
# 1. Root CA (offline, air-gapped ideal)
openssl genrsa -aes256 -out root-ca.key 4096
openssl req -x509 -new -nodes -key root-ca.key -sha256 -days 3650 -out root-ca.crt -subj "/CN=megaminer Root CA"

# 2. Server cert (API + Stratum)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=megaminer.local"
openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile <(echo -e "subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# 3. Client cert (mTLS futuro)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=megaminer-admin"
openssl x509 -req -in client.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile <(echo -e "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth")
```

#### Cert Pinning — Obtención Fingerprint (Pool Stratum)
```bash
# Conectar al pool y extraer fingerprint SHA-256 del cert
openssl s_client -connect pool.example.com:3334 -servername pool.example.com -showcerts </dev/null 2>/dev/null | \
  openssl x509 -fingerprint -sha256 -noout | cut -d'=' -f2 | tr -d ':'
# Output ejemplo: A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890

# Usar en config:
# --pool-cert-pin A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890
```

### 2.2 Pool Config Seguro (`pools.conf`)
```json
{
  "pools": [
    {
      "url": "stratum+tl://pool.example.com:3334",
      "user": "wallet.worker",
      "pass": "x",
      "cert_pin": "A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890",
      "tls_verify": true,
      "priority": 1
    },
    {
      "url": "stratum+tl://backup.pool.com:3334",
      "user": "wallet.worker",
      "pass": "x",
      "cert_pin": "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
      "tls_verify": true,
      "priority": 2
    }
  ],
  "failover": true,
  "no_plaintext": true
}
```

**Reglas obligatorias**:
- ✅ Solo `stratum+tl://` (TLS)
- ✅ `cert_pin` en **todos** los pools
- ✅ `tls_verify: true`
- ❌ **NUNCA** `stratum+tcp://` ni `stratum://` sin pinning

### 2.3 API Bind + TLS (Obligatorio)
```bash
# Solo loopback (default seguro)
./megaminer --api-bind 127.0.0.1:4028 --api-tls-cert server.crt --api-tls-key server.key

# Si DEBE exponerse LAN (excepcional, documentado):
./megaminer --api-bind 0.0.0.0:4028 --api-tls-cert server.crt --api-tls-key server.key --api-mtls-ca root-ca.crt
# Requiere mTLS + client cert — Basic Auth DESHABILITADO en este modo
```

### 2.4 Permisos Archivos Sensibles
```bash
# Windows (PowerShell como Admin)
icacls server.key /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" "megaminer_svc:(R)"
icacls server.crt /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" "megaminer_svc:(R)"
icacls pools.conf /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" "megaminer_svc:(R)"

# Linux/macOS
chmod 600 server.key pools.conf
chmod 644 server.crt
chown megaminer:megaminer server.key server.crt pools.conf
```

---

## 3. Deployment Hardening

### 3.1 Firewall Rules (Windows Defender / nftables / iptables)

#### Windows (PowerShell Admin)
```powershell
# 1. Bloquear todo entrante por defecto
Set-NetFirewallProfile -All -DefaultInboundAction Block

# 2. Permitir SOLO API en loopback (no crea regla entrante real, solo local)
#    La bind 127.0.0.1 ya aísla — esta regla es defensa en profundidad
New-NetFirewallRule -DisplayName "megaminer API Loopback" -Direction Inbound -LocalAddress 127.0.0.1 -LocalPort 4028 -Protocol TCP -Action Allow -Profile Any

# 3. Stratum OUTBOUND only (pool connections)
New-NetFirewallRule -DisplayName "megaminer Stratum Outbound" -Direction Outbound -RemotePort 3333,3334 -Protocol TCP -Action Allow -Profile Any -Program "C:\path\megaminer.exe"

# 4. Bloquear todo lo demás outbound no esencial
New-NetFirewallRule -DisplayName "megaminer Block Other Outbound" -Direction Outbound -Action Block -Profile Any -Program "C:\path\megaminer.exe" # Excepto reglas arriba (orden importa)
```

#### Linux (nftables)
```bash
#!/usr/sbin/nft -f
table inet megaminer {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept                                    # Loopback
        ct state established,related accept             # Established
        tcp dport 4028 ip saddr 127.0.0.1 accept        # API solo localhost
        icmp type echo-request limit rate 1/second accept
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oif lo accept
        ct state established,related accept
        tcp dport { 3333, 3334 } accept                 # Stratum pools
        udp dport 53 accept                             # DNS
        tcp dport 443 accept                            # HTTPS (updates, metrics push)
    }
}
```

### 3.2 Monitoring — Prometheus `/metrics`

#### Métricas Clave (Alertas)
| Métrica | Tipo | Descripción | Alert Threshold |
|---------|------|-------------|-----------------|
| `megaminer_hashrate` | Gauge | Hashrate actual (H/s) | `< 0.8 * expected` 5m |
| `megaminer_shares_accepted_total` | Counter | Shares aceptados | Rate drop > 50% 5m |
| `megaminer_shares_rejected_total` | Counter | Shares rechazados | `> 0.05 * accepted` |
| `megaminer_stratum_connected` | Gauge | Conexión pool (1/0) | `== 0` 1m |
| `megaminer_api_requests_total` | Counter | Requests API por endpoint | Spike > 10x baseline |
| `megaminer_gpu_temperature_celsius` | Gauge | Temp GPU | `> 85` sustained |
| `megaminer_gpu_power_watts` | Gauge | Power draw | `> TDP * 1.1` |
| `megaminer_circuit_breaker_state` | Gauge | 0=closed, 1=open, 2=half-open | `== 1` > 30s |
| `megaminer_nvml_errors_total` | Counter | Errores NVML | `> 0` |

#### Prometheus Rule File (`alerts/megaminer.yml`)
```yaml
groups:
- name: megaminer
  interval: 30s
  rules:
  - alert: MegaminerStratumDisconnected
    expr: megaminer_stratum_connected == 0
    for: 1m
    labels: { severity: critical }
    annotations:
      summary: "Stratum disconnected"
      description: "Pool connection lost for 1m. Check network/pool cert pin."

  - alert: MegaminerHashrateDrop
    expr: megaminer_hashrate < 0.8 * on(instance) group_left megaminer_expected_hashrate
    for: 5m
    labels: { severity: warning }
    annotations:
      summary: "Hashrate dropped >20%"
      description: "Current: {{ $value }} H/s, Expected: {{ $labels.expected }}"

  - alert: MegaminerHighRejectRate
    expr: rate(megaminer_shares_rejected_total[5m]) / rate(megaminer_shares_accepted_total[5m]) > 0.05
    for: 5m
    labels: { severity: warning }
    annotations:
      summary: "Reject rate >5%"
      description: "Check pool difficulty, stale shares, or pool issues."

  - alert: MegaminerGPUOverheat
    expr: megaminer_gpu_temperature_celsius > 85
    for: 2m
    labels: { severity: critical }
    annotations:
      summary: "GPU overheating"
      description: "GPU {{ $labels.gpu }} at {{ $value }}°C. Throttle or shutdown."

  - alert: MegaminerCircuitBreakerOpen
    expr: megaminer_circuit_breaker_state == 1
    for: 30s
    labels: { severity: warning }
    annotations:
      summary: "Circuit breaker OPEN"
      description: "API/Stratum circuit breaker open. Check upstream health."

  - alert: MegaminerNVMLErrors
    expr: increase(megaminer_nvml_errors_total[5m]) > 0
    for: 1m
    labels: { severity: critical }
    annotations:
      summary: "NVML errors detected"
      description: "Driver/GPU communication errors. Check dmesg, driver version."
```

### 3.3 Log Forwarding (Structured JSON)
```json
{
  "timestamp": "2026-10-28T14:32:11.123Z",
  "level": "WARN",
  "component": "stratum",
  "event": "cert_pin_mismatch",
  "pool": "pool.example.com:3334",
  "expected_pin": "A1B2...",
  "received_pin": "DEAD...",
  "action": "connection_terminated"
}
```
- **Sink**: Loki / Elastic / Splunk via `stdout` JSON lines
- **Retención**: 90 días hot, 1 año cold

---

## 4. Incident Response — Runbook Refs

| Incidente | Runbook (Elijas) | Detección | Contención | Recuperación |
|-----------|------------------|-----------|------------|--------------|
| **MITM Stratum** | `runbooks/mitm_stratum.md` | Alert `MegaminerStratumDisconnected` + cert pin mismatch logs | Kill miner, rotate pool certs, verify new pins | Re-deploy con nuevos pins, post-mortem |
| **GPU Brick** | `runbooks/gpu_brick.md` | Alert `MegaminerGPUOverheat` + `nvml_errors` + hashrate 0 | Emergency shutdown (`--shutdown-temp`), power cycle GPU | Driver reinstall, hardware diag, RMA si necesario |
| **API Takeover** | `runbooks/api_takeover.md` | Alert `MegaminerHighRejectRate` + anomalous API calls + unknown client certs | Firewall block API port, revoke certs, rotate credentials | Forensic image, cert re-issue, mTLS enforcement |
| **Socket Leak / FD Exhaustion** | `runbooks/socket_leak.md` | `megaminer_open_fds` > 90% limit, circuit breaker open | Graceful restart (SIGTERM), connection drain | Root cause: connection pool sizing, fix + deploy |

**Runbook Template** (cada uno debe tener):
```markdown
# Runbook: [Nombre]
## Síntomas / Alertas
## Diagnóstico Rápido (5 min)
## Contención Inmediata
## Investigación Profunda
## Recuperación
## Post-Mortem Template
## Contactos Escalation
```

---

## 5. Checklist Pre-Release (10 Ítems — Veto Scotynau)

> **Regla**: **Cualquier ❌ = NO RELEASE**. Scotynau tiene veto absoluto.

| # | Ítem | Verificación | Evidencia Requerida | Owner |
|---|------|--------------|---------------------|-------|
| **1** | **Build flags hardening** | `dumpbin /loadconfig` muestra CFG, CET, ASLR, DEP, GS | Log CI + artifact `hardening-report.txt` | Build Eng |
| **2** | **vcpkg pinned + baseline fijo** | `vcpkg-configuration.json` commit hash = CI lockfile | `vcpkg lock` output en artifacts | Build Eng |
| **3** | **SBOM generado + firmado** | `cyclonedx-bom.json` + `cosign sign` | SBOM + signature en release assets | Security |
| **4** | **TLS certs válidos + pinning pools** | `openssl verify` + `cert_pin` match en todos los pools | Script `verify-pins.ps1` output | Release Eng |
| **5** | **API bind 127.0.0.1 default** | Binary default config = loopback only | `strings megaminer.exe | findstr 127.0.0.1` | QA |
| **6** | **Rate limit + circuit breaker funcionales** | Chaos test: 1000 req/s → 429 + breaker open | Elijas chaos report (automated) | Chaos Eng |
| **7** | **DLL safe loading verificado** | Process Monitor: `LoadLibraryExW` con flags correctos | ProcMon log + code review | Security |
| **8** | **NVML retry + state verify** | Inyectar fallo NVML → retry backoff + state check | Unit test + integration test log | GPU Eng |
| **9** | **Firewall rules aplicadas + test** | `Test-NetConnection` falla desde LAN a API port | Network test matrix (CI stage) | DevOps |
| **10** | **Runbooks actualizados + drill ejecutado** | Último drill < 30 días, docs en `runbooks/` | Drill log + 참석자 sign-off | SRE Lead |

### Ejecución Automatizada (CI Gate)
```yaml
# .github/workflows/release-gate.yml
jobs:
  pre-release-checklist:
    runs-on: windows-2025
    steps:
      - uses: actions/checkout@v4
      - name: Run hardening verification
        run: |
          ./scripts/verify-hardening.ps1 -Binary megaminer.exe -Config pools.conf
      - name: Scotynau veto check
        run: |
          if (Get-Content veto-check.json | ConvertFrom-Json).any_failed {
            Write-Error "SCOTYNAU VETO: Pre-release checklist failed"
            exit 1
          }
```

---

## 6. Quick Reference — Command Line Flags (Seguridad)

| Flag | Descripción | Default | Seguro? |
|------|-------------|---------|---------|
| `--api-bind` | API bind address | `127.0.0.1:4028` | ✅ Solo loopback |
| `--api-tls-cert` | TLS cert file | **Requerido si bind != 127.0.0.1** | ✅ Obligatorio |
| `--api-tls-key` | TLS key file | **Requerido si bind != 127.0.0.1** | ✅ Obligatorio |
| `--api-mtls-ca` | CA para mTLS client verify | (none) | ✅ Requerido para 0.0.0.0 |
| `--pool-cert-pin` | SHA-256 fingerprint pool cert | **Requerido por pool** | ✅ Obligatorio |
| `--no-plaintext-stratum` | Rechazar pools sin TLS | `true` | ✅ Hardcoded |
| `--shutdown-temp` | Emergency GPU shutdown temp (°C) | `90` | ✅ Safety |
| `--watchdog` | Enable hardware watchdog | `true` | ✅ Enabled |

---

## 7. Versionamento y Deprecación

| Versión | Cambio Crítico | Acción Requerida |
|---------|----------------|------------------|
| **v2.0** | mTLS API obligatorio para bind 0.0.0.0 | Migrar a client certs |
| **v2.1** | Stratum plaintext hard-fail (reject por defecto) | Actualizar todos los pools a TLS+pin |
| **v3.0** | GPU kernel sandbox (WDDM 3.0) | Driver update + kernel recompile |

---

> **Recordatorio**: Este documento es **vivo**. Cada release actualiza checksums, pins, y runbooks.
> **"Tolerancia cero a la mediocridad."** — Scotynau