#!/usr/bin/env python3
"""
Capability analyzer - Identifies dangerous Linux capabilities
that can lead to container escape
"""

import tempfile
from pathlib import Path
from typing import List

from .base import BaseScanner, Finding, Severity, Exploitability


class CapabilityScanner(BaseScanner):
    """Analyze Linux capabilities for escape vectors"""
    
    # Capabilities with known escape paths
    DANGEROUS_CAPABILITIES = {
        "CAP_SYS_ADMIN": {
            "severity": Severity.CRITICAL,
            "vectors": [
                "Mount namespace manipulation",
                "Cgroup release_agent escape",
                "Kernel module loading",
                "BPF program loading",
            ],
            "remediation": "Never grant CAP_SYS_ADMIN to containers. Use granular capabilities or device plugins."
        },
        "CAP_SYS_PTRACE": {
            "severity": Severity.HIGH,
            "vectors": [
                "Process injection into host processes",
                "Reading memory of privileged processes",
                "Bypassing namespace restrictions via ptrace",
            ],
            "remediation": "Remove CAP_SYS_PTRACE unless absolutely necessary for debugging."
        },
        "CAP_SYS_MODULE": {
            "severity": Severity.CRITICAL,
            "vectors": [
                "Load arbitrary kernel modules",
                "Direct kernel memory manipulation",
            ],
            "remediation": "Never grant CAP_SYS_MODULE. This capability is rarely needed in containers."
        },
        "CAP_DAC_READ_SEARCH": {
            "severity": Severity.HIGH,
            "vectors": [
                "Bypass file read permission checks",
                "Access to host files through /proc",
                "Read sensitive files like /etc/shadow",
            ],
            "remediation": "Remove CAP_DAC_READ_SEARCH and use volume mounts with specific permissions."
        },
        "CAP_DAC_OVERRIDE": {
            "severity": Severity.HIGH,
            "vectors": [
                "Bypass file write permission checks",
                "Modify critical system files",
            ],
            "remediation": "Remove CAP_DAC_OVERRIDE unless specifically required."
        },
        "CAP_NET_ADMIN": {
            "severity": Severity.MEDIUM,
            "vectors": [
                "Network namespace escape",
                "ARP poisoning",
                "Traffic interception",
            ],
            "remediation": "Use host network mode carefully. Prefer bridge networks."
        },
        "CAP_NET_RAW": {
            "severity": Severity.MEDIUM,
            "vectors": [
                "Raw socket creation",
                "Packet sniffing",
                "ARP spoofing",
            ],
            "remediation": "Remove unless network diagnostics are required."
        },
        "CAP_SYS_CHROOT": {
            "severity": Severity.MEDIUM,
            "vectors": [
                "Second chroot escape",
                "Breaking out of container rootfs",
            ],
            "remediation": "Remove CAP_SYS_CHROOT - containers already use pivot_root."
        },
        "CAP_SYS_BOOT": {
            "severity": Severity.HIGH,
            "vectors": [
                "Reboot the host system",
            ],
            "remediation": "Never grant CAP_SYS_BOOT to containers."
        },
        "CAP_SYS_RAWIO": {
            "severity": Severity.CRITICAL,
            "vectors": [
                "Direct hardware access",
                "Memory-mapped I/O attacks",
            ],
            "remediation": "Never grant CAP_SYS_RAWIO."
        },
        "CAP_BPF": {
            "severity": Severity.HIGH,
            "vectors": [
                "Load eBPF programs",
                "Kernel tracing and manipulation",
            ],
            "remediation": "Disable unprivileged BPF via kernel.unprivileged_bpf_disabled=1."
        },
        "CAP_PERFMON": {
            "severity": Severity.MEDIUM,
            "vectors": [
                "Performance monitoring access",
                "Potential information disclosure",
            ],
            "remediation": "Remove unless performance profiling is required."
        },
    }
    
    def _verify_cap_sys_admin(self) -> bool:
        """Verify CAP_SYS_ADMIN exploitability via mount test"""
        if not self.verify_mode:
            return False
        
        try:
            # Try to mount a tmpfs - requires CAP_SYS_ADMIN
            with tempfile.TemporaryDirectory() as tmpdir:
                result = self._run_command([
                    "mount", "-t", "tmpfs", "tmpfs", tmpdir
                ])
                if result is not None and "permission denied" not in result.lower():
                    # Cleanup
                    self._run_command(["umount", tmpdir])
                    return True
        except:
            pass
        return False
    
    def _verify_cap_dac_read_search(self) -> bool:
        """Verify CAP_DAC_READ_SEARCH by attempting to read restricted file"""
        if not self.verify_mode:
            return False
        
        # Try to read /etc/shadow which should be restricted
        try:
            with open("/etc/shadow", "r") as f:
                content = f.read()
                return len(content) > 0
        except:
            return False
    
    def scan(self) -> List[Finding]:
        """Scan for dangerous capabilities"""
        
        if not self._is_container:
            self.add_finding(Finding(
                module="capabilities",
                title="Not running in container",
                description="Capability scanner expects to run inside a container. Results may be inaccurate.",
                severity=Severity.INFO,
                exploitability=Exploitability.UNLIKELY,
            ))
        
        # Check for privileged mode
        all_caps_present = all(self._capabilities.values()) if self._capabilities else False
        if all_caps_present:
            self.add_finding(Finding(
                module="capabilities",
                title="Container running in privileged mode",
                description="All capabilities are granted. This is equivalent to root on the host.",
                severity=Severity.CRITICAL,
                exploitability=Exploitability.CONFIRMED,
                technical_details={"mode": "privileged"},
                remediation="Never run containers with --privileged flag. Drop all capabilities and add only those required.",
                references=[
                    "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
                ]
            ))
        
        # Check individual dangerous capabilities
        for cap_name, cap_info in self.DANGEROUS_CAPABILITIES.items():
            if self._capabilities.get(cap_name, False):
                exploitability = Exploitability.LIKELY
                poc_output = None
                
                # Verify if requested
                if self.verify_mode:
                    if cap_name == "CAP_SYS_ADMIN" and self._verify_cap_sys_admin():
                        exploitability = Exploitability.CONFIRMED
                        poc_output = "Mount test succeeded - CAP_SYS_ADMIN is fully functional"
                    elif cap_name == "CAP_DAC_READ_SEARCH" and self._verify_cap_dac_read_search():
                        exploitability = Exploitability.CONFIRMED
                        poc_output = "Successfully read /etc/shadow - file permissions bypassed"
                
                self.add_finding(Finding(
                    module="capabilities",
                    title=f"Dangerous capability present: {cap_name}",
                    description=f"Container has {cap_name} capability.\n\nEscape vectors:\n" + 
                               "\n".join(f"  • {v}" for v in cap_info["vectors"]),
                    severity=cap_info["severity"],
                    exploitability=exploitability,
                    technical_details={
                        "capability": cap_name,
                        "present": True,
                        "all_capabilities": self._capabilities,
                    },
                    remediation=cap_info["remediation"],
                    poc_output=poc_output,
                    references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"]
                ))
        
        return self.findings
