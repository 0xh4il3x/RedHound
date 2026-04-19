#!/usr/bin/env python3
"""
RedHound - Red Team Container Assessment Framework
Command-line interface
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from scanner.base import Finding, Severity, Exploitability
from scanner.capabilities import CapabilityScanner
from scanner.sockets import SocketScanner
from scanner.mounts import MountScanner
from scanner.namespaces import NamespaceScanner
from scanner.cgroups import CgroupScanner
from scanner.cloud import CloudMetadataScanner
from scanner.k8s import KubernetesScanner
from scanner.cves import CVEScanner
from utils.colors import Colors
from exploit.verifier import PoCVerifier, Verdict, VerificationResult


class RedHoundCLI:
    """Main CLI handler for RedHound"""
    
    def __init__(self):
        self.scanners = []
        self.findings: List[Finding] = []
        
    def setup_scanners(self, verify_mode: bool = False, modules: List[str] = None):
        """Initialize scanner modules"""
        scanner_map = {
            "capabilities": CapabilityScanner,
            "sockets": SocketScanner,
            "mounts": MountScanner,
            "namespaces": NamespaceScanner,
            "cgroups": CgroupScanner,
            "cloud": CloudMetadataScanner,
            "k8s": KubernetesScanner,
            "cves": CVEScanner,
        }
        
        if modules is None:
            modules = list(scanner_map.keys())
        
        for module in modules:
            if module in scanner_map:
                self.scanners.append(scanner_map[module](verify_mode=verify_mode))
    
    def run_scan(self) -> List[Finding]:
        """Execute all configured scanners"""
        for scanner in self.scanners:
            scanner.scan()
            self.findings.extend(scanner.findings)
        return self.findings
    
    def generate_report(self, findings: List[Finding], format_type: str = "terminal"):
        """Generate report in specified format"""
        
        if format_type == "json":
            return self._json_report(findings)
        elif format_type == "markdown":
            return self._markdown_report(findings)
        else:
            return self._terminal_report(findings)
    
    def _terminal_report(self, findings: List[Finding]) -> str:
        """Generate colored terminal output"""
        
        severity_colors = {
            Severity.CRITICAL: Colors.RED,
            Severity.HIGH: Colors.YELLOW,
            Severity.MEDIUM: Colors.BLUE,
            Severity.LOW: Colors.GREEN,
            Severity.INFO: Colors.WHITE,
        }
        
        exploitability_icons = {
            Exploitability.CONFIRMED: "🔴",
            Exploitability.LIKELY: "🟡",
            Exploitability.POTENTIAL: "🟠",
            Exploitability.UNLIKELY: "⚪",
            Exploitability.FALSE_POSITIVE: "✓",
        }
        
        output = []
        output.append(f"\n{Colors.BOLD}=== RedHound Container Security Assessment ==={Colors.END}\n")
        output.append(f"Scan Time: {datetime.now().isoformat()}")
        output.append(f"Total Findings: {len(findings)}\n")
        
        # Group by severity
        findings_by_severity = {}
        for finding in findings:
            if finding.severity not in findings_by_severity:
                findings_by_severity[finding.severity] = []
            findings_by_severity[finding.severity].append(finding)
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity not in findings_by_severity:
                continue
            
            color = severity_colors[severity]
            output.append(f"\n{color}{Colors.BOLD}[{severity.value}]{Colors.END}")
            output.append("=" * 60)
            
            for finding in findings_by_severity[severity]:
                icon = exploitability_icons[finding.exploitability]
                output.append(f"\n{icon} {Colors.BOLD}{finding.title}{Colors.END}")
                output.append(f"   Module: {finding.module}")
                output.append(f"   Exploitability: {finding.exploitability.value}")
                output.append(f"\n   {finding.description[:200]}...")
                
                if finding.poc_output:
                    output.append(f"   {Colors.GREEN}PoC Output: {finding.poc_output}{Colors.END}")
                
                if finding.remediation:
                    output.append(f"\n   {Colors.CYAN}→ Remediation: {finding.remediation}{Colors.END}")
        
        output.append(f"\n{Colors.BOLD}=== Assessment Complete ==={Colors.END}\n")
        return "\n".join(output)
    
    def _json_report(self, findings: List[Finding]) -> str:
        """Generate JSON report"""
        report = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": []
        }
        
        for finding in findings:
            report["findings"].append({
                "module": finding.module,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "exploitability": finding.exploitability.value,
                "technical_details": finding.technical_details,
                "remediation": finding.remediation,
                "references": finding.references,
                "poc_output": finding.poc_output,
            })
        
        return json.dumps(report, indent=2)
    
    def _markdown_report(self, findings: List[Finding]) -> str:
        """Generate Markdown report"""
        output = []
        output.append("# RedHound Container Security Assessment\n")
        output.append(f"**Scan Time:** {datetime.now().isoformat()}")
        output.append(f"**Total Findings:** {len(findings)}\n")
        output.append("---\n")
        
        # Summary table
        output.append("## Summary by Severity\n")
        output.append("| Severity | Count |")
        output.append("|----------|-------|")
        
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(severity, 0)
            output.append(f"| {severity.value} | {count} |")
        
        output.append("\n## Detailed Findings\n")
        
        for finding in findings:
            output.append(f"### {finding.title}\n")
            output.append(f"**Module:** {finding.module}  ")
            output.append(f"**Severity:** {finding.severity.value}  ")
            output.append(f"**Exploitability:** {finding.exploitability.value}\n")
            output.append(f"{finding.description}\n")
            
            if finding.technical_details:
                output.append("**Technical Details:**")
                output.append("```json")
                output.append(json.dumps(finding.technical_details, indent=2))
                output.append("```\n")
            
            if finding.poc_output:
                output.append("**Proof of Concept Output:**")
                output.append("```")
                output.append(finding.poc_output)
                output.append("```\n")
            
            if finding.remediation:
                output.append(f"**Remediation:** {finding.remediation}\n")
            
            if finding.references:
                output.append("**References:**")
                for ref in finding.references:
                    output.append(f"- {ref}")
                output.append("")
            
            output.append("---\n")
        
        return "\n".join(output)


def verify_command(args):
    """Run verification tests"""
    verifier = PoCVerifier()
    
    print(f"{Colors.BOLD}=== RedHound Exploitability Verification ==={Colors.END}\n")
    
    if args.module == "all" or args.module == "capabilities":
        print(f"{Colors.BOLD}Testing CAP_SYS_ADMIN...{Colors.END}")
        result = verifier.verify_cap_sys_admin()
        print_result(result)
    
    if args.module == "all" or args.module == "sockets":
        print(f"{Colors.BOLD}Testing Docker Socket...{Colors.END}")
        result = verifier.verify_docker_socket_access()
        print_result(result)
    
    if args.module == "all" or args.module == "cgroups":
        print(f"{Colors.BOLD}Testing Cgroup Release Agent...{Colors.END}")
        result = verifier.verify_cgroup_release_agent()
        print_result(result)
    
    if args.module == "all" or args.module == "procfs":
        print(f"{Colors.BOLD}Testing ProcFS Escape...{Colors.END}")
        result = verifier.verify_procfs_escape()
        print_result(result)
    
    if args.module == "all" or args.module == "cloud":
        print(f"{Colors.BOLD}Testing Cloud Metadata...{Colors.END}")
        result = verifier.verify_cloud_metadata_access(
            "http://169.254.169.254/latest/meta-data/"
        )
        print_result(result)
    
    verifier.cleanup()


def print_result(result: VerificationResult):
    """Print verification result with color"""
    color_map = {
        Verdict.EXPLOITABLE: Colors.RED,
        Verdict.VULNERABLE: Colors.YELLOW,
        Verdict.SAFE: Colors.GREEN,
        Verdict.BLOCKED: Colors.BLUE,
        Verdict.INCONCLUSIVE: Colors.WHITE,
    }
    
    color = color_map[result.verdict]
    print(f"  {color}Verdict: {result.verdict.value}{Colors.END}")
    print(f"  Details: {result.details}")
    if result.evidence:
        print(f"  Evidence: {result.evidence[:200]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="RedHound - Red Team Container Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  redhound scan                           # Run all scanners
  redhound scan --verify                  # Verify exploitability with safe PoCs
  redhound scan --modules capabilities    # Run only capability scanner
  redhound scan --format json             # Output JSON report
  redhound scan --format markdown -o report.md  # Save to file
  redhound verify --module capabilities   # Verify specific attack vector
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute", required=True)
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("--verify", action="store_true",
                             help="Verify exploitability with safe PoC tests")
    scan_parser.add_argument("--modules", nargs="+",
                             choices=["capabilities", "sockets", "mounts", "namespaces", "cgroups", "cloud", "k8s", "cves"],
                             help="Specific modules to run")
    scan_parser.add_argument("--format", choices=["terminal", "json", "markdown"],
                             default="terminal", help="Output format")
    scan_parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Run exploitability verification")
    verify_parser.add_argument("--module", choices=["all", "capabilities", "sockets", "cgroups", "procfs", "cloud"],
                               default="all", help="Module to verify")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        cli = RedHoundCLI()
        cli.setup_scanners(verify_mode=args.verify, modules=args.modules)
        findings = cli.run_scan()
        report = cli.generate_report(findings, format_type=args.format)
        
        if args.output:
            Path(args.output).write_text(report)
            print(f"Report saved to {args.output}")
        else:
            print(report)
        
        # Return exit code based on findings
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        if critical_count > 0:
            sys.exit(1)
        sys.exit(0)
    
    elif args.command == "verify":
        verify_command(args)


if __name__ == "__main__":
    main()
