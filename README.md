# ccminer

Modified to add support for X16R (Ravencoin). Work in progress... lots of room for improvement. Use `-a x16r` and `--num-fallback-threads n` where n is > 0.

[Windows x64 builds](https://github.com/todd1251/ccminer-x16r/releases)

[Ubuntu 16.08 build instructions](https://github.com/todd1251/ccminer-x16r/wiki/Ubuntu-16.08-build)

BTC donation address: 1AJdfCpLWPNoAMDfHF1wD5y8VgKSSTHxPo (tpruvot)

RVN donation address: RWoyvvT5exmbs937QfRavf4fxB5mvijG6R (penfold)

RVN donation address: RE9hcu1LjVbzL1wzsnpnJP28B2x2Y4qc55 (phabit)

---

Based on Christian Buchner's &amp; Christian H.'s CUDA project, no more active on github since 2014.

Check the [README.txt](README.txt) for the additions

BTC donation address: 1AJdfCpLWPNoAMDfHF1wD5y8VgKSSTHxPo (tpruvot)

A part of the recent algos were originally written by [djm34](https://github.com/djm34) and [alexis78](https://github.com/alexis78)

This variant was tested and built on Linux (ubuntu server 14.04, 16.04, Fedora 22 to 25)
It is also built for Windows 7 to 10 with VStudio 2013, to stay compatible with Windows 7 and Vista.

Note that the x86 releases are generally faster than x64 ones on Windows, but that tend to change with the recent drivers.

The recommended CUDA Toolkit version was the [6.5.19](http://developer.download.nvidia.com/compute/cuda/6_5/rel/installers/cuda_6.5.19_windows_general_64.exe), but some light algos could be faster with the version 7.5 and 8.0 (like lbry, decred and skein).

About source code dependencies
------------------------------

This project requires some libraries to be built :

- OpenSSL (prebuilt for win)
- Curl (prebuilt for win)
- pthreads (prebuilt for win)

The tree now contains recent prebuilt openssl and curl .lib for both x86 and x64 platforms (windows).

To rebuild them, you need to clone this repository and its submodules :
    git clone https://github.com/peters/curl-for-windows.git compat/curl-for-windows


Compile on Linux
----------------

Please see [INSTALL](https://github.com/tpruvot/ccminer/blob/linux/INSTALL) file or [project Wiki](https://github.com/tpruvot/ccminer/wiki/Compatibility)

## Security Features

### Hardcoded SSL Verification

SSL certificate verification (`CURLOPT_SSL_VERIFYPEER=1`) is now hardcoded and cannot be disabled by the user. This prevents man-in-the-middle attacks on pool connections.

### Certificate Pinning for Pools

Certificate pinning ensures that only pools with known, trusted certificates are accepted. This prevents attackers from using fraudulent certificates issued by compromised CAs.

**Usage:**

```bash
# Add a certificate pin for a custom pool
ccminer --pool-cert-pin=pool.example.com:sha256:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890
```

**Format:** `host:sha256:HEX` where HEX is the 64-character lowercase SHA-256 fingerprint of the pool's leaf certificate.

**Behavior:**
- Known pools (pre-configured pins): Must match exactly or connection fails
- Custom pools (via `--pool-cert-pin`): Must match exactly or connection fails
- Unknown pools (no pin configured): Connection allowed but warning logged

**Example with multiple pins:**

```bash
ccminer -o stratum+tcp://pool1.example.com:3333 \
        --pool-cert-pin=pool1.example.com:sha256:a1b2c3d4... \
        --pool-cert-pin=pool2.example.com:sha256:e5f6a7b8...
```

### Obtaining Certificate SHA-256 Fingerprint

To get the SHA-256 fingerprint of a pool's certificate:

```bash
# Using OpenSSL
openssl s_client -connect pool.example.com:443 -servername pool.example.com </dev/null 2>/dev/null | \
  openssl x509 -fingerprint -sha256 -noout | \
  sed 's/://g' | cut -d= -f2 | tr '[:upper:]' '[:lower:]'
```

Or for Stratum TLS (if supported):

```bash
openssl s_client -connect pool.example.com:3333 -servername pool.example.com </dev/null 2>/dev/null | \
  openssl x509 -fingerprint -sha256 -noout | \
  sed 's/://g' | cut -d= -f2 | tr '[:upper:]' '[:lower:]'
```

---

## API: WebSocket Deprecation & SSE Events

### `--api-no-ws` Flag

The legacy WebSocket API uses SHA-1 for the handshake (RFC 6455), which is cryptographically deprecated. To disable WebSocket and avoid legacy crypto:

```bash
ccminer --api-no-ws -b 127.0.0.1:4068
```

**Behavior:**
- WebSocket upgrade requests (`Sec-WebSocket-Key` header) return **HTTP 400** with JSON error:
  ```json
  {"error":"WebSocket disabled (SHA-1 deprecated). Use REST API + SSE /events"}
  ```
- REST API endpoints (`/summary`, `/pool`, `/threads`, etc.) continue to work normally
- Default: WebSocket enabled (`--api-no-ws=false`) for backward compatibility

### SSE `/events` Endpoint (Recommended Replacement)

Server-Sent Events (SSE) provides real-time streaming over HTTP/2 + TLS without legacy crypto handshake.

**Endpoint:** `GET /events` (or `GET https://host:port/events` with TLS)

**Response:** `Content-Type: text/event-stream`

**Event format:**
```text
event: stats
data: NAME=ccminer;VER=1.0;API=1.9;ALGO=x16r;GPUS=2;KHS=1234.56;SOLV=10;ACC=100;REJ=2;ACCMN=5.000;DIFF=1.234567;NETKHS=500000;POOLS=1;WAIT=0;UPTIME=3600;TS=1234567890|GPU=0;BUS=1;CARD=RTX 3080;TEMP=65.2;POWER=250;FAN=60;RPM=2400;FREQ=1800;MEMFREQ=9500;GPUF=1800;MEMF=9500;KHS=617.28;KHW=2.469;PLIM=100;ACC=50;REJ=1;HWF=0;I=20.0;THR=0|GPU=1;BUS=2;CARD=RTX 3080;TEMP=63.8;POWER=245;FAN=58;RPM=2350;FREQ=1800;MEMFREQ=9500;GPUF=1800;MEMF=9500;KHS=617.28;KHW=2.520;PLIM=100;ACC=50;REJ=1;HWF=0;I=20.0;THR=1|

event: stats
data: NAME=ccminer;VER=1.0;API=1.9;ALGO=x16r;GPUS=2;KHS=1235.12;SOLV=10;ACC=101;REJ=2;ACCMN=5.020;DIFF=1.234567;NETKHS=500000;POOLS=1;WAIT=0;UPTIME=3602;TS=1234567892|...
```

**Client example (curl):**
```bash
curl -N http://127.0.0.1:4068/events
```

**Client example (JavaScript/TypeScript):**
```javascript
const evtSource = new EventSource('https://miner.local:4068/events');
evtSource.addEventListener('stats', (e) => {
  const data = e.data; // pipe-delimited key=value pairs
  const summary = parsePipeData(data); // parse NAME, KHS, ACC, REJ, etc.
  updateDashboard(summary);
});
```

**Advantages over WebSocket:**
- No SHA-1 handshake (uses standard TLS)
- Works over HTTP/2 multiplexed connections
- Automatic reconnection built into browser EventSource API
- Simpler client implementation (no framing protocol)
- Firewall/proxy friendly (standard HTTP)
