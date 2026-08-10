# FarhansAnsibleCollection

A collection of Ansible playbooks for server maintenance and provisioning, optimized for use with [Semaphore UI](https://semaphoreui.com/).

## Project Structure

```
playbooks/
├── maintenance/
│   ├── quick-inventory-check.yml   # Connectivity & uptime check
│   └── update-servers.yml          # Cross-distro patch management
└── provisioning/
    ├── deploy-ssl-certs.yml        # SSL certificate deployment
    └── install-netbird.yml         # NetBird VPN agent setup
```

## Playbooks

### Maintenance

#### `quick-inventory-check.yml`

Lightweight connectivity check across all hosts. Tests SSH + Python availability via `ping`, then reports uptime. Skips fact gathering for speed.

```bash
ansible-playbook playbooks/maintenance/quick-inventory-check.yml -i inventory
```

#### `update-servers.yml`

Cross-distro patching that handles:

| Distro Family | Legacy | Modern |
|---|---|---|
| Debian / Ubuntu | ≤ Debian 10 / Ubuntu 20 (`apt-get` via shell) | Debian 11+ / Ubuntu 22+ (`apt` module) |
| RHEL / CentOS / Rocky | ≤ CentOS 7 (`yum` via shell) | CentOS / Rocky 8+ (`dnf` module) |

```bash
ansible-playbook playbooks/maintenance/update-servers.yml -i inventory
```

### Provisioning

#### `install-netbird.yml`

Installs and connects the [NetBird](https://netbird.io) VPN agent. Idempotent — skips install if `/usr/bin/netbird` exists and skips connection if already connected.

**Required Variables:**

| Variable | Description |
|---|---|
| `target_server` | Host or group to target |
| `netbird_management_url` | NetBird management server URL |
| `netbird_setup_key` | Setup key for peer enrollment |
| `enable_netbird_ssh` | *(Optional, default: `false`)* Enable SSH tunneling via NetBird |

```bash
# Standard connection
ansible-playbook playbooks/provisioning/install-netbird.yml -i inventory \
  -e "target_server=webservers" \
  -e "netbird_management_url=https://api.netbird.io:443" \
  -e "netbird_setup_key=YOUR_SETUP_KEY"

# With SSH enabled
ansible-playbook playbooks/provisioning/install-netbird.yml -i inventory \
  -e "target_server=webservers" \
  -e "netbird_management_url=https://api.netbird.io:443" \
  -e "netbird_setup_key=YOUR_SETUP_KEY" \
  -e "enable_netbird_ssh=true"
```

#### `deploy-ssl-certs.yml`

Deploys SSL certificates and private keys to the standard Linux directories (`/etc/ssl/certs/` and `/etc/ssl/private/`) with correct ownership and permissions. Certificate and key content are passed as variables, making it compatible with Semaphore surveys (paste PEM content directly). Supports optional CA chain deployment.

**Required Variables:**

| Variable | Description |
|---|---|
| `target_server` | Host or group to target |
| `ssl_cert_content` | PEM-encoded certificate content |
| `ssl_key_content` | PEM-encoded private key content |
| `cert_filename` | *(Optional, default: `server.crt`)* Certificate filename |
| `key_filename` | *(Optional, default: `server.key`)* Private key filename |
| `ssl_chain_content` | *(Optional)* PEM-encoded CA chain content |
| `ssl_chain_filename` | *(Optional, default: `ca-chain.crt`)* CA chain filename |

**Permissions Applied:**

| File | Owner | Group | Mode |
|---|---|---|---|
| Certificate | `root` | `root` | `0644` |
| Private Key | `root` | `ssl-cert` | `0640` |
| CA Chain | `root` | `root` | `0644` |

```bash
# Production deployment
ansible-playbook playbooks/provisioning/deploy-ssl-certs.yml -i inventory \
  -e "target_server=webservers" \
  -e "cert_filename=example.com.crt" \
  -e "key_filename=example.com.key" \
  -e "ssl_cert_content='-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----'" \
  -e "ssl_key_content='-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----'"

# Test run with a sample file and custom filename
ansible-playbook playbooks/provisioning/deploy-ssl-certs.yml -i inventory \
  -e "target_server=testserver" \
  -e "cert_filename=test-sample.crt" \
  -e "key_filename=test-sample.key" \
  -e "ssl_cert_content='test certificate content'" \
  -e "ssl_key_content='test key content'"
```

## Configuration

The included `ansible.cfg` is tuned for performance:

- **25 forks** for parallel execution
- **SSH pipelining** with `ControlPersist` for connection reuse
- **JSON fact caching** (2 hour TTL) to avoid redundant host scans
- **Semaphore-friendly** output callbacks (`timer`, `profile_tasks`)
