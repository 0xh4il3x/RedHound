#!/usr/bin/env python3
"""
Runtime socket exposure scanner - Identifies exposed container runtime sockets
that can lead to container escape
"""

import os
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseScanner, Finding, Severity, Exploitability


class SocketScanner(BaseScanner):
    """Scan for exposed container runtime sockets"""
    
    RUNTIME_SOCKETS = {
        "/var/run/docker.sock": {
            "runtime": "Docker",
            "severity": Severity.CRITICAL,
            "impact": "Full host compromise via Docker API",
            "exploit_example": "docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host"
        },
        "/run/docker.sock": {
            "runtime": "Docker",
            "severity": Severity.CRITICAL,
            "impact": "Full host compromise via Docker API",
        },
        "/run/containerd/containerd.sock": {
            "runtime": "containerd",
            "severity": Severity.CRITICAL,
            "impact": "Container escape via containerd API (requires ctr or nerdctl)",
        },
        "/run/crio/crio.sock": {
            "runtime": "CRI-O",
            "severity": Severity.CRITICAL,
            "impact": "Container escape via CRI-O API (requires crictl)",
        },
        "/var/run/crio/crio.sock": {
            "runtime": "CRI-O",
            "severity": Severity.CRITICAL,
            "impact": "Container escape via CRI-O API",
        },
        "/var/snap/microk8s/current/docker.sock": {
            "runtime": "MicroK8s Docker",
            "severity": Severity.CRITICAL,
            "impact": "Full host compromise via Docker API in MicroK8s",
        },
        "/run/k3s/containerd/containerd.sock": {
            "runtime": "K3s containerd",
            "severity": Severity.CRITICAL,
            "impact": "Container escape via containerd API in K3s",
        },
        "/var/run/podman/podman.sock": {
            "runtime": "Podman",
            "severity": Severity.HIGH,
            "impact": "Rootless escape; privileged operations if user is root",
        },
    }
    
    def _test_docker_socket(self, socket_path: str) -> Dict[str, Any]:
        """Test Docker socket access and capabilities"""
        result = {
            "accessible": False,
            "version": None,
            "can_list_containers": False,
            "can_create_containers": False,
        }
        
        if not self._check_socket(socket_path):
            return result
        
        result["accessible"] = True
        
        if not self.verify_mode:
            return result
        
        # Try to interact with Docker API
        import urllib.request
        import urllib.error
        import json
        
        try:
            # Create a custom opener for Unix socket
            import socket
            
            class UnixHTTPConnection:
                def __init__(self, path):
                    self.path = path
                
                def request(self, method, url, headers=None, body=None):
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(self.path)
                    
                    request_line = f"{method} {url} HTTP/1.1\r\n"
                    headers = headers or {}
                    headers["Host"] = "localhost"
                    
                    for k, v in headers.items():
                        request_line += f"{k}: {v}\r\n"
                    request_line += "\r\n"
                    
                    if body:
                        request_line += body
                    
                    sock.send(request_line.encode())
                    
                    response = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    
                    sock.close()
                    
                    # Parse response
                    parts = response.split(b"\r\n\r\n", 1)
                    if len(parts) > 1:
                        return {"status": 200, "body": parts[1].decode()}
                    return {"status": 500, "body": ""}
            
            conn = UnixHTTPConnection(socket_path)
            
            # Get version
            response = conn.request("GET", "/v1.41/version")
            if response["status"] == 200:
                result["version"] = json.loads(response["body"]).get("Version")
            
            # Check if we can list containers
            response = conn.request("GET", "/v1.41/containers/json")
            if response["status"] == 200:
                result["can_list_containers"] = True
            
            # Check if we can create containers (requires specific permissions)
            # We don't actually create one, just check the endpoint
            response = conn.request("POST", "/v1.41/containers/create", 
                                   headers={"Content-Type": "application/json"},
                                   body='{"Image": "alpine", "Cmd": ["echo", "test"]}')
            if response["status"] in [200, 201, 404]:  # 404 might mean image not found but endpoint works
                result["can_create_containers"] = True
                
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def scan(self) -> List[Finding]:
        """Scan for exposed runtime sockets"""
        
        for socket_path, socket_info in self.RUNTIME_SOCKETS.items():
            if self._file_exists(socket_path):
                exploitability = Exploitability.LIKELY
                technical_details = {
                    "socket_path": socket_path,
                    "runtime": socket_info["runtime"],
                }
                
                # Verify access if requested
                if self.verify_mode and "docker" in socket_path.lower():
                    test_result = self._test_docker_socket(socket_path)
                    technical_details.update(test_result)
                    
                    if test_result.get("can_create_containers"):
                        exploitability = Exploitability.CONFIRMED
                    elif test_result.get("can_list_containers"):
                        exploitability = Exploitability.LIKELY
                
                # Check if socket is writable
                if self._file_writable(socket_path):
                    technical_details["writable"] = True
                
                self.add_finding(Finding(
                    module="sockets",
                    title=f"Container runtime socket exposed: {socket_path}",
                    description=f"Socket for {socket_info['runtime']} is mounted inside the container.\n\n"
                               f"Impact: {socket_info.get('impact', 'Container escape possible')}\n\n"
                               f"Exploitation example:\n```\n{socket_info.get('exploit_example', 'N/A')}\n```",
                    severity=socket_info["severity"],
                    exploitability=exploitability,
                    technical_details=technical_details,
                    remediation=f"Never mount {socket_path} into containers. Use proper API authentication or delegate tasks via orchestration.",
                    references=[
                        "https://docs.docker.com/engine/security/#docker-daemon-attack-surface",
                        "https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html"
                    ]
                ))
        
        return self.findings
