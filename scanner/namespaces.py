#!/usr/bin/env python3
"""
Namespace scanner - Identifies namespace escape vectors
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Set

from .base import BaseScanner, Finding, Severity, Exploitability


class NamespaceScanner(BaseScanner):
    """Scan for namespace isolation weaknesses"""
    
    NAMESPACE_TYPES = ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup", "time"]
    
    def __init__(self, verify_mode: bool = False):
        super().__init__(verify_mode)
        self.namespaces = self._get_namespaces()
        self.host_namespaces = self._get_host_namespaces()
    
    def _get_namespaces(self) -> Dict[str, str]:
        """Get current process namespaces"""
        namespaces = {}
        try:
            proc_self = Path("/proc/self/ns")
            if proc_self.exists():
                for ns_file in proc_self.iterdir():
                    try:
                        link = os.readlink(str(ns_file))
                        namespaces[ns_file.name] = link
                    except:
                        pass
        except:
            pass
        return namespaces
    
    def _get_host_namespaces(self) -> Dict[str, str]:
        """Get host init process namespaces"""
        namespaces = {}
        try:
            proc_1 = Path("/proc/1/ns")
            if proc_1.exists():
                for ns_file in proc_1.iterdir():
                    try:
                        link = os.readlink(str(ns_file))
                        namespaces[ns_file.name] = link
                    except:
                        pass
        except:
            pass
        return namespaces
    
    def _check_namespace_sharing(self) -> List[Dict[str, Any]]:
        """Check which namespaces are shared with host"""
        shared = []
        
        for ns_type in self.NAMESPACE_TYPES:
            if ns_type in self.namespaces and ns_type in self.host_namespaces:
                if self.namespaces[ns_type] == self.host_namespaces[ns_type]:
                    shared.append({
                        "namespace": ns_type,
                        "container_ns": self.namespaces[ns_type],
                        "host_ns": self.host_namespaces[ns_type],
                        "shared": True
                    })
        
        return shared
    
    def _check_user_namespace(self) -> Dict[str, Any]:
        """Check user namespace configuration"""
        user_ns_info = {
            "enabled": False,
            "uid_map": None,
            "root_in_ns": False,
        }
        
        try:
            uid_map = Path("/proc/self/uid_map").read_text().strip()
            user_ns_info["uid_map"] = uid_map
            
            # Check if we're root in the namespace
            if os.geteuid() == 0:
                user_ns_info["root_in_ns"] = True
            
            # Check if user namespace is enabled
            if "user" in self.namespaces:
                user_ns_info["enabled"] = True
                
                # Check if we're mapped to root on host
                if uid_map and "0" in uid_map.split()[0]:
                    user_ns_info["mapped_to_host_root"] = True
        except:
            pass
        
        return user_ns_info
    
    def _check_pid_namespace_escape(self) -> bool:
        """Check if we can see host processes"""
        try:
            procs = list(Path("/proc").glob("[0-9]*"))
            # In a proper container, we should only see a few processes
            # If we see many processes, likely sharing PID namespace
            return len(procs) > 10
        except:
            return False
    
    def _verify_namespace_escape(self) -> Dict[str, bool]:
        """Test various namespace escape techniques"""
        results = {
            "nsenter_available": False,
            "unshare_available": False,
            "can_enter_host_mnt": False,
        }
        
        if not self.verify_mode:
            return results
        
        # Check for nsenter binary
        nsenter_paths = ["/usr/bin/nsenter", "/bin/nsenter", "/usr/local/bin/nsenter"]
        for path in nsenter_paths:
            if self._file_exists(path) and os.access(path, os.X_OK):
                results["nsenter_available"] = True
                break
        
        # Check for unshare binary
        unshare_paths = ["/usr/bin/unshare", "/bin/unshare"]
        for path in unshare_paths:
            if self._file_exists(path) and os.access(path, os.X_OK):
                results["unshare_available"] = True
                break
        
        # Test if we can enter host mount namespace
        if results["nsenter_available"]:
            try:
                # Try to run a harmless command in host mount namespace
                output = self._run_command([
                    "nsenter", "-t", "1", "-m", "--", "echo", "test"
                ])
                if output and "test" in output:
                    results["can_enter_host_mnt"] = True
            except:
                pass
        
        return results
    
    def scan(self) -> List[Finding]:
        """Scan for namespace vulnerabilities"""
        
        # Check shared namespaces
        shared_ns = self._check_namespace_sharing()
        for ns in shared_ns:
            severity = Severity.CRITICAL if ns["namespace"] in ["mnt", "pid"] else Severity.HIGH
            
            self.add_finding(Finding(
                module="namespaces",
                title=f"Shared namespace with host: {ns['namespace']}",
                description=f"Container shares {ns['namespace']} namespace with host.\n"
                           f"This significantly weakens container isolation.",
                severity=severity,
                exploitability=Exploitability.CONFIRMED,
                technical_details=ns,
                remediation=f"Use --{ns['namespace']}=private or don't share {ns['namespace']} namespace",
                references=[
                    "https://docs.docker.com/engine/reference/run/#pid-settings---pid"
                ]
            ))
        
        # Check PID namespace isolation
        if self._check_pid_namespace_escape():
            self.add_finding(Finding(
                module="namespaces",
                title="PID namespace isolation weak or shared",
                description="Container can see many host processes, indicating PID namespace is shared or not properly isolated.",
                severity=Severity.HIGH,
                exploitability=Exploitability.CONFIRMED,
                technical_details={"visible_processes": "Many"},
                remediation="Ensure --pid=host is not used unless absolutely necessary",
            ))
        
        # Check user namespace
        user_ns_info = self._check_user_namespace()
        if user_ns_info["enabled"]:
            self.add_finding(Finding(
                module="namespaces",
                title="User namespace enabled",
                description="Container is using user namespace remapping",
                severity=Severity.INFO,
                exploitability=Exploitability.UNLIKELY,
                technical_details=user_ns_info,
                remediation="User namespaces are good for security - keep enabled",
            ))
        else:
            if user_ns_info["root_in_ns"]:
                self.add_finding(Finding(
                    module="namespaces",
                    title="Running as root without user namespace",
                    description="Container is running as root without user namespace remapping.\n"
                               "Root in container equals root on host for many operations.",
                    severity=Severity.HIGH,
                    exploitability=Exploitability.LIKELY,
                    technical_details=user_ns_info,
                    remediation="Enable user namespace remapping or run as non-root user",
                    references=[
                        "https://docs.docker.com/engine/security/userns-remap/"
                    ]
                ))
        
        # Verify namespace escape capabilities
        escape_checks = self._verify_namespace_escape()
        if escape_checks["nsenter_available"]:
            severity = Severity.CRITICAL if escape_checks["can_enter_host_mnt"] else Severity.HIGH
            self.add_finding(Finding(
                module="namespaces",
                title="nsenter binary available",
                description="nsenter tool is available in container, which can be used for namespace escape",
                severity=severity,
                exploitability=Exploitability.CONFIRMED if escape_checks["can_enter_host_mnt"] else Exploitability.LIKELY,
                technical_details=escape_checks,
                remediation="Remove nsenter binary from container image",
                references=[
                    "https://man7.org/linux/man-pages/man1/nsenter.1.html"
                ]
            ))
        
        if escape_checks["unshare_available"]:
            self.add_finding(Finding(
                module="namespaces",
                title="unshare binary available",
                description="unshare tool can be used to create new namespaces and potentially escape",
                severity=Severity.MEDIUM,
                exploitability=Exploitability.LIKELY,
                technical_details=escape_checks,
                remediation="Remove unshare binary if not needed",
            ))
        
        return self.findings
