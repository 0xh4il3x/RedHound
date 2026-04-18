#!/usr/bin/env python3
"""
Cgroup scanner - Identifies cgroup escape vectors (CVE-2022-0492, release_agent, etc.)
"""

import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseScanner, Finding, Severity, Exploitability


class CgroupScanner(BaseScanner):
    """Scan for cgroup escape vulnerabilities"""
    
    def __init__(self, verify_mode: bool = False):
        super().__init__(verify_mode)
        self.cgroup_version = self._detect_cgroup_version()
        self.cgroup_mounts = self._get_cgroup_mounts()
    
    def _detect_cgroup_version(self) -> int:
        """Detect cgroup v1 or v2"""
        try:
            if Path("/sys/fs/cgroup/cgroup.controllers").exists():
                return 2
            elif Path("/sys/fs/cgroup").exists():
                return 1
        except:
            pass
        return 0
    
    def _get_cgroup_mounts(self) -> List[Dict[str, Any]]:
        """Get cgroup mount information"""
        mounts = []
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    if "cgroup" in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            mounts.append({
                                "device": parts[0],
                                "mountpoint": parts[1],
                                "fstype": parts[2],
                                "options": parts[3].split(","),
                            })
        except:
            pass
        return mounts
    
    def _check_release_agent_escape(self) -> Dict[str, Any]:
        """Check for release_agent escape vector (cgroup v1)"""
        result = {
            "vulnerable": False,
            "reason": "",
            "paths": []
        }
        
        if self.cgroup_version != 1:
            result["reason"] = f"Cgroup v{self.cgroup_version} detected, release_agent is v1 only"
            return result
        
        # Check for writable cgroup directories
        for mount in self.cgroup_mounts:
            mountpoint = Path(mount["mountpoint"])
            
            # Check release_agent file
            release_agent = mountpoint / "release_agent"
            if release_agent.exists():
                if self._file_writable(str(release_agent)):
                    result["vulnerable"] = True
                    result["paths"].append({
                        "path": str(release_agent),
                        "writable": True,
                        "type": "release_agent"
                    })
            
            # Check notify_on_release
            for subdir in mountpoint.glob("*/"):
                notify_file = subdir / "notify_on_release"
                if notify_file.exists() and self._file_writable(str(notify_file)):
                    result["vulnerable"] = True
                    result["paths"].append({
                        "path": str(notify_file),
                        "writable": True,
                        "type": "notify_on_release"
                    })
        
        return result
    
    def _check_cgroup_v2_escape(self) -> Dict[str, Any]:
        """Check for cgroup v2 escape vectors"""
        result = {
            "vulnerable": False,
            "reason": "",
            "checks": {}
        }
        
        if self.cgroup_version != 2:
            result["reason"] = f"Cgroup v{self.cgroup_version} detected, not v2"
            return result
        
        # Check if we can write to cgroup.procs in root cgroup
        root_cgroup = Path("/sys/fs/cgroup")
        cgroup_procs = root_cgroup / "cgroup.procs"
        
        if cgroup_procs.exists():
            writable = self._file_writable(str(cgroup_procs))
            result["checks"]["root_cgroup_procs_writable"] = writable
            
            # Check if we can move processes between cgroups
            try:
                # Try to read current cgroup
                cgroup_path = Path("/proc/self/cgroup").read_text()
                result["checks"]["current_cgroup"] = cgroup_path.strip()
            except:
                pass
        
        return result
    
    def _check_cve_2022_0492(self) -> Dict[str, Any]:
        """Check for CVE-2022-0492 (cgroup v1 release_agent escape)"""
        result = {
            "vulnerable": False,
            "caps_present": [],
            "unconfined": False
        }
        
        # Check for required capabilities
        required_caps = ["CAP_SYS_ADMIN"]
        for cap in required_caps:
            if self._capabilities.get(cap, False):
                result["caps_present"].append(cap)
        
        # Check if AppArmor/SELinux is enforcing
        try:
            with open("/proc/self/attr/current", "r") as f:
                label = f.read().strip()
                if "unconfined" in label:
                    result["unconfined"] = True
                result["label"] = label
        except:
            pass
        
        # If we have CAP_SYS_ADMIN and cgroup v1, likely vulnerable
        if "CAP_SYS_ADMIN" in result["caps_present"] and self.cgroup_version == 1:
            # Check release_agent configuration
            release_check = self._check_release_agent_escape()
            if release_check["vulnerable"]:
                result["vulnerable"] = True
                result["release_agent_info"] = release_check
        
        return result
    
    def _verify_release_agent_escape(self) -> Optional[str]:
        """Safely verify release_agent escape without actual exploitation"""
        if not self.verify_mode:
            return None
        
        if self.cgroup_version != 1:
            return "Cgroup v1 not detected"
        
        # Try to create a test cgroup
        test_cgroup = "/tmp/test_redhound_cgroup"
        try:
            # Create cgroup
            os.makedirs(test_cgroup, exist_ok=True)
            
            # Mount cgroup (requires CAP_SYS_ADMIN)
            result = self._run_command([
                "mount", "-t", "cgroup", "-o", "rdma", "cgroup", test_cgroup
            ])
            
            if result and "permission denied" not in result.lower():
                # Check if we can write to release_agent
                release_agent = Path(test_cgroup) / "release_agent"
                if release_agent.exists():
                    try:
                        release_agent.write_text("/bin/sh")
                        return "Release agent write successful - ESCAPE POSSIBLE"
                    except:
                        return "Release agent exists but not writable"
            
            # Cleanup
            self._run_command(["umount", test_cgroup])
            os.rmdir(test_cgroup)
            
        except Exception as e:
            return f"Verification failed: {str(e)}"
        
        return "Verification inconclusive"
    
    def scan(self) -> List[Finding]:
        """Scan for cgroup vulnerabilities"""
        
        # Report cgroup version
        self.add_finding(Finding(
            module="cgroups",
            title=f"Cgroup version {self.cgroup_version} detected",
            description=f"Container is using cgroup v{self.cgroup_version}",
            severity=Severity.INFO,
            exploitability=Exploitability.UNLIKELY,
            technical_details={
                "cgroup_version": self.cgroup_version,
                "mounts": self.cgroup_mounts
            },
        ))
        
        # Check for release_agent escape (v1)
        release_check = self._check_release_agent_escape()
        if release_check["vulnerable"]:
            poc_output = None
            exploitability = Exploitability.LIKELY
            
            if self.verify_mode:
                poc_output = self._verify_release_agent_escape()
                if poc_output and "ESCAPE POSSIBLE" in poc_output:
                    exploitability = Exploitability.CONFIRMED
            
            self.add_finding(Finding(
                module="cgroups",
                title="Cgroup v1 release_agent escape vector detected",
                description="Container can write to cgroup release_agent file, which can lead to host code execution.\n"
                           "This is a well-known container escape technique.",
                severity=Severity.CRITICAL,
                exploitability=exploitability,
                technical_details=release_check,
                poc_output=poc_output,
                remediation="Use cgroup v2, enable seccomp profile, or drop CAP_SYS_ADMIN",
                references=[
                    "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
                    "https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html"
                ]
            ))
        
        # Check for CVE-2022-0492
        cve_check = self._check_cve_2022_0492()
        if cve_check["vulnerable"]:
            self.add_finding(Finding(
                module="cgroups",
                title="CVE-2022-0492: cgroup v1 escape vulnerability",
                description="Container is vulnerable to CVE-2022-0492, which allows container escape via cgroup release_agent",
                severity=Severity.CRITICAL,
                exploitability=Exploitability.LIKELY,
                technical_details=cve_check,
                remediation="Update kernel to patched version, use cgroup v2, or drop CAP_SYS_ADMIN",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
                    "https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/"
                ]
            ))
        
        # Check cgroup v2 issues
        v2_check = self._check_cgroup_v2_escape()
        if v2_check["checks"].get("root_cgroup_procs_writable"):
            self.add_finding(Finding(
                module="cgroups",
                title="Cgroup v2 root cgroup.procs is writable",
                description="Container can write to root cgroup.procs, which may allow process migration and resource manipulation",
                severity=Severity.MEDIUM,
                exploitability=Exploitability.POTENTIAL,
                technical_details=v2_check,
                remediation="Ensure proper cgroup v2 delegation or use cgroup namespace isolation",
            ))
        
        return self.findings
