#!/usr/bin/env python3
"""
Mount point scanner - Identifies sensitive mounts that can lead to container escape
"""

import os
import stat
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseScanner, Finding, Severity, Exploitability


class MountScanner(BaseScanner):
    """Scan for dangerous mount points"""
    
    SENSITIVE_MOUNTS = {
        "/var/run/docker.sock": {
            "type": "socket",
            "severity": Severity.CRITICAL,
            "impact": "Docker API access - full host compromise",
            "remediation": "Never mount the Docker socket into containers"
        },
        "/run/docker.sock": {
            "type": "socket",
            "severity": Severity.CRITICAL,
            "impact": "Docker API access - full host compromise",
        },
        "/": {
            "type": "filesystem",
            "severity": Severity.CRITICAL,
            "impact": "Full host filesystem access",
            "remediation": "Mount specific directories only, never the root filesystem"
        },
        "/host": {
            "type": "filesystem",
            "severity": Severity.CRITICAL,
            "impact": "Common host filesystem mount point",
        },
        "/proc": {
            "type": "procfs",
            "severity": Severity.HIGH,
            "impact": "Access to host process information, potential process injection",
            "remediation": "Mount /proc with hidepid=2 option or avoid mounting"
        },
        "/sys": {
            "type": "sysfs",
            "severity": Severity.HIGH,
            "impact": "Access to kernel parameters and device configuration",
            "remediation": "Mount /sys as read-only or avoid mounting"
        },
        "/dev": {
            "type": "devfs",
            "severity": Severity.HIGH,
            "impact": "Access to host devices, potential raw disk access",
            "remediation": "Use --device for specific devices instead of mounting /dev"
        },
        "/var/run": {
            "type": "directory",
            "severity": Severity.MEDIUM,
            "impact": "Access to host runtime files and sockets",
        },
        "/var/log": {
            "type": "directory",
            "severity": Severity.MEDIUM,
            "impact": "Access to host logs, potential credential leakage",
        },
        "/etc": {
            "type": "directory",
            "severity": Severity.HIGH,
            "impact": "Access to host configuration files (passwd, shadow, ssh keys)",
        },
        "/root": {
            "type": "directory",
            "severity": Severity.CRITICAL,
            "impact": "Access to root user's home directory and SSH keys",
        },
        "/home": {
            "type": "directory",
            "severity": Severity.HIGH,
            "impact": "Access to user home directories and SSH keys",
        },
    }
    
    def __init__(self, verify_mode: bool = False):
        super().__init__(verify_mode)
        self.mounts = self._parse_mounts()
    
    def _parse_mounts(self) -> List[Dict[str, Any]]:
        """Parse /proc/mounts for mount information"""
        mounts = []
        try:
            content = Path("/proc/mounts").read_text()
            for line in content.splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    mounts.append({
                        "device": parts[0],
                        "mountpoint": parts[1],
                        "fstype": parts[2],
                        "options": parts[3].split(","),
                        "dump": parts[4],
                        "pass": parts[5],
                    })
        except:
            pass
        return mounts
    
    def _is_mounted(self, path: str) -> Optional[Dict[str, Any]]:
        """Check if a path is mounted and return mount info"""
        for mount in self.mounts:
            if mount["mountpoint"] == path or mount["mountpoint"].startswith(path + "/"):
                return mount
        return None
    
    def _check_bind_mount_escape(self) -> List[Dict[str, Any]]:
        """Check for bind mounts that allow escape to host"""
        escapes = []
        
        for mount in self.mounts:
            # Check if we're in a container and can access host paths
            if mount["mountpoint"].startswith("/host") or "/host" in mount["mountpoint"]:
                escapes.append({
                    "type": "host_bind_mount",
                    "mount": mount,
                    "exploitability": "Host filesystem directly accessible"
                })
            
            # Check for /proc/1/root access
            if mount["mountpoint"] == "/proc" and "rw" in mount["options"]:
                proc_root = Path("/proc/1/root")
                if proc_root.exists():
                    try:
                        # Try to list host root
                        list(proc_root.iterdir())
                        escapes.append({
                            "type": "procfs_escape",
                            "mount": mount,
                            "path": "/proc/1/root",
                            "exploitability": "Can access host filesystem via /proc/1/root"
                        })
                    except:
                        pass
        
        return escapes
    
    def _check_device_access(self) -> List[Dict[str, Any]]:
        """Check for accessible host devices"""
        devices = []
        device_paths = ["/dev/sda", "/dev/sda1", "/dev/nvme0n1", "/dev/xvda", "/dev/vda"]
        
        for dev_path in device_paths:
            if self._file_exists(dev_path):
                try:
                    mode = os.stat(dev_path).st_mode
                    readable = bool(mode & stat.S_IRUSR)
                    writable = bool(mode & stat.S_IWUSR)
                    
                    devices.append({
                        "path": dev_path,
                        "readable": readable,
                        "writable": writable,
                        "type": "block_device"
                    })
                except:
                    pass
        
        return devices
    
    def _verify_write_access(self, path: str) -> bool:
        """Verify write access to a path with safe test"""
        if not self.verify_mode:
            return False
        
        test_file = Path(path) / ".redhound_test"
        try:
            test_file.write_text("test")
            test_file.unlink()
            return True
        except:
            return False
    
    def scan(self) -> List[Finding]:
        """Scan for dangerous mounts"""
        
        # Check sensitive mounts
        for mount_path, mount_info in self.SENSITIVE_MOUNTS.items():
            mount = self._is_mounted(mount_path)
            if mount:
                exploitability = Exploitability.LIKELY
                technical_details = {
                    "mount_path": mount_path,
                    "mount_info": mount,
                    "type": mount_info["type"]
                }
                
                # Verify write access for filesystem mounts
                if mount_info["type"] in ["filesystem", "directory"]:
                    if self._verify_write_access(mount_path):
                        exploitability = Exploitability.CONFIRMED
                        technical_details["writable"] = True
                
                self.add_finding(Finding(
                    module="mounts",
                    title=f"Sensitive mount detected: {mount_path}",
                    description=f"Container has access to {mount_info['type']} {mount_path}\n\n"
                               f"Impact: {mount_info['impact']}",
                    severity=mount_info["severity"],
                    exploitability=exploitability,
                    technical_details=technical_details,
                    remediation=mount_info.get("remediation", "Remove this mount from container configuration"),
                    references=[
                        "https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface"
                    ]
                ))
        
        # Check for bind mount escape vectors
        escapes = self._check_bind_mount_escape()
        for escape in escapes:
            self.add_finding(Finding(
                module="mounts",
                title=f"Container escape possible via {escape['type']}",
                description=f"Bind mount configuration allows host filesystem access\n\n"
                           f"Escape path: {escape.get('path', escape['mount']['mountpoint'])}\n"
                           f"Exploitability: {escape['exploitability']}",
                severity=Severity.CRITICAL,
                exploitability=Exploitability.CONFIRMED,
                technical_details=escape,
                remediation="Avoid mounting /proc or use hidepid=2. Don't bind mount host root.",
                references=[
                    "https://blog.pentesteracademy.com/container-security-escape-via-procfs-1eb94c3f0b3d"
                ]
            ))
        
        # Check for device access
        devices = self._check_device_access()
        for device in devices:
            severity = Severity.CRITICAL if device["writable"] else Severity.HIGH
            self.add_finding(Finding(
                module="mounts",
                title=f"Host block device accessible: {device['path']}",
                description=f"Container can access host block device\n"
                           f"Readable: {device['readable']}, Writable: {device['writable']}",
                severity=severity,
                exploitability=Exploitability.CONFIRMED if device["writable"] else Exploitability.LIKELY,
                technical_details=device,
                remediation="Never mount /dev into containers. Use --device for specific devices.",
                references=[
                    "https://docs.docker.com/engine/reference/commandline/run/#mount"
                ]
            ))
        
        return self.findings
