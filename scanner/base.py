#!/usr/bin/env python3
"""
RedHound - Red Team Container Assessment Framework
Base scanner module providing core detection primitives
"""

import os
import stat
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Exploitability(Enum):
    CONFIRMED = "CONFIRMED"      # PoC verified - escape possible
    LIKELY = "LIKELY"            # Conditions present, high confidence
    POTENTIAL = "POTENTIAL"      # Conditions present, requires specific trigger
    UNLIKELY = "UNLIKELY"        # Conditions present but constrained
    FALSE_POSITIVE = "FALSE"     # Checked and not exploitable


@dataclass
class Finding:
    """Represents a single security finding"""
    module: str
    title: str
    description: str
    severity: Severity
    exploitability: Exploitability
    technical_details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    poc_output: Optional[str] = None


class BaseScanner(ABC):
    """Abstract base class for all scanner modules"""
    
    def __init__(self, verify_mode: bool = False):
        self.verify_mode = verify_mode  # Enable PoC verification
        self.findings: List[Finding] = []
        self._is_container = self._detect_container()
        self._capabilities = self._get_capabilities()
        
    def _detect_container(self) -> bool:
        """Detect if we're running inside a container"""
        checks = [
            Path("/.dockerenv").exists(),
            Path("/run/.containerenv").exists(),
            "container" in Path("/proc/1/cgroup").read_text() if Path("/proc/1/cgroup").exists() else False,
        ]
        return any(checks)
    
    def _get_capabilities(self) -> Dict[str, bool]:
        """Parse current process capabilities"""
        caps = {}
        try:
            # Read capsh output for comprehensive capability list
            result = subprocess.run(
                ["capsh", "--print"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            for line in result.stdout.splitlines():
                if "Bounding set" in line:
                    caps_str = line.split("=")[1].strip()
                    # Map capability names to boolean presence
                    all_caps = self._get_all_capabilities()
                    for cap in all_caps:
                        caps[cap] = cap.lower().replace("cap_", "") in caps_str.lower()
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fallback: check /proc/self/status
            try:
                status = Path("/proc/self/status").read_text()
                for line in status.splitlines():
                    if line.startswith("CapEff:"):
                        eff_mask = int(line.split(":")[1].strip(), 16)
                        caps = self._decode_capabilities(eff_mask)
            except:
                pass
        return caps
    
    def _get_all_capabilities(self) -> List[str]:
        """Return list of all Linux capabilities"""
        return [
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
            "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",
            "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
            "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
            "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
            "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        ]
    
    def _decode_capabilities(self, mask: int) -> Dict[str, bool]:
        """Decode capability bitmask"""
        caps = {}
        all_caps = self._get_all_capabilities()
        for i, cap in enumerate(all_caps):
            caps[cap] = bool(mask & (1 << i))
        return caps
    
    def _run_command(self, cmd: List[str], timeout: int = 10) -> Optional[str]:
        """Safely execute command and return output"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout + result.stderr
        except:
            return None
    
    def _file_exists(self, path: str) -> bool:
        """Check if file exists and is accessible"""
        try:
            return Path(path).exists()
        except:
            return False
    
    def _file_readable(self, path: str) -> bool:
        """Check if file is readable"""
        try:
            return os.access(path, os.R_OK)
        except:
            return False
    
    def _file_writable(self, path: str) -> bool:
        """Check if file/directory is writable"""
        try:
            return os.access(path, os.W_OK)
        except:
            return False
    
    def _check_socket(self, path: str) -> bool:
        """Check if a Unix socket exists and is accessible"""
        try:
            return stat.S_ISSOCK(Path(path).stat().st_mode)
        except:
            return False
    
    def add_finding(self, finding: Finding):
        """Add a finding to the scanner results"""
        self.findings.append(finding)
    
    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scanner module - must be implemented by subclasses"""
        pass
