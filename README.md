# RedHound - Red Team Container Security Scanner

Red team container security scanner. Finds escape vectors from inside a container.

## Installation

```bash
git clone https://github.com/yourusername/redhound.git
cd redhound
```

## Usage

```bash
python3 cli.py scan
python3 cli.py scan --verify
python3 cli.py scan --modules capabilities sockets mounts
python3 cli.py scan --format json -o report.json
python3 cli.py scan --format markdown -o report.md
python3 cli.py verify --module capabilities
python3 cli.py verify --module all
```

## Modules

| Module       | Checks                                |
|--------------|----------------------------------------|
| capabilities | Dangerous Linux capabilities           |
| sockets      | Docker/containerd socket exposure      |
| mounts       | Sensitive filesystem mounts            |
| namespaces   | Shared host namespaces                 |
| cgroups      | cgroup escape vectors                  |
| cloud        | Cloud metadata service access          |
| k8s          | Kubernetes service account tokens      |
| cves         | Known container escape CVEs            |

## Requirements

```text
- Linux host (uses /proc, /sys, capabilities, cgroups)
- Python 3.6+
- Run inside the target container
```

## Example

```bash
docker exec -it vulnerable-container sh
cd /tmp/redhound
python3 cli.py scan --verify
```

## Output Severity

```text
CRITICAL - Immediate container escape possible
HIGH     - Likely privilege escalation path
MEDIUM   - Potential attack vector
LOW      - Minor issue
INFO     - Informational
```
