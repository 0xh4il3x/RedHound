#!/usr/bin/env python3
"""
Kubernetes scanner - Identifies K8s pivoting vectors and service account exposure
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseScanner, Finding, Severity, Exploitability


class KubernetesScanner(BaseScanner):
    """Scan for Kubernetes attack vectors"""
    
    K8S_PATHS = {
        "service_account": {
            "token": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "ca": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "namespace": "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        },
        "kube_config": [
            "/root/.kube/config",
            "/home/user/.kube/config",
            "/.kube/config",
            "/etc/kubernetes/admin.conf",
        ],
        "kubelet_api": "https://${KUBERNETES_SERVICE_HOST}:10250",
    }
    
    def __init__(self, verify_mode: bool = False):
        super().__init__(verify_mode)
        self.service_account_token = self._get_service_account_token()
        self.k8s_env = self._get_k8s_environment()
    
    def _get_service_account_token(self) -> Optional[str]:
        """Read service account token if available"""
        token_path = Path(self.K8S_PATHS["service_account"]["token"])
        if token_path.exists():
            try:
                return token_path.read_text().strip()
            except:
                pass
        return None
    
    def _get_k8s_environment(self) -> Dict[str, str]:
        """Get Kubernetes environment variables"""
        k8s_vars = {}
        for key, value in os.environ.items():
            if key.startswith("KUBERNETES_"):
                k8s_vars[key] = value
        return k8s_vars
    
    def _check_service_account_permissions(self) -> Dict[str, Any]:
        """Check service account permissions by querying K8s API"""
        result = {
            "can_list_pods": False,
            "can_create_pods": False,
            "can_list_secrets": False,
            "can_exec_pods": False,
            "namespace": None,
            "api_accessible": False,
        }
        
        if not self.service_account_token:
            return result
        
        host = self.k8s_env.get("KUBERNETES_SERVICE_HOST")
        port = self.k8s_env.get("KUBERNETES_SERVICE_PORT")
        
        if not host or not port:
            return result
        
        # Read namespace
        ns_path = Path(self.K8S_PATHS["service_account"]["namespace"])
        if ns_path.exists():
            result["namespace"] = ns_path.read_text().strip()
        
        if not self.verify_mode:
            return result
        
        # Test API access
        import urllib.request
        import urllib.error
        import ssl
        
        try:
            ca_path = self.K8S_PATHS["service_account"]["ca"]
            api_base = f"https://{host}:{port}"
            
            # Create unverified context (we just want to test access)
            context = ssl._create_unverified_context()
            
            headers = {
                "Authorization": f"Bearer {self.service_account_token}",
                "Content-Type": "application/json",
            }
            
            # Test pod listing
            ns = result["namespace"] or "default"
            req = urllib.request.Request(
                f"{api_base}/api/v1/namespaces/{ns}/pods",
                headers=headers
            )
            
            try:
                with urllib.request.urlopen(req, context=context, timeout=5) as resp:
                    if resp.status == 200:
                        result["can_list_pods"] = True
                        result["api_accessible"] = True
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    result["api_accessible"] = True  # API accessible but forbidden
            
            # Test secret listing
            req = urllib.request.Request(
                f"{api_base}/api/v1/namespaces/{ns}/secrets",
                headers=headers
            )
            
            try:
                with urllib.request.urlopen(req, context=context, timeout=5) as resp:
                    if resp.status == 200:
                        result["can_list_secrets"] = True
            except:
                pass
            
        except Exception as e:
            pass
        
        return result
    
    def _check_kubelet_api(self) -> Dict[str, Any]:
        """Check Kubelet API accessibility"""
        result = {
            "accessible": False,
            "anonymous_auth": False,
            "can_list_pods": False,
        }
        
        host = self.k8s_env.get("KUBERNETES_SERVICE_HOST")
        if not host:
            return result
        
        kubelet_url = f"https://{host}:10250/pods"
        
        if not self.verify_mode:
            return result
        
        import urllib.request
        import ssl
        
        try:
            context = ssl._create_unverified_context()
            req = urllib.request.Request(kubelet_url)
            
            with urllib.request.urlopen(req, context=context, timeout=5) as resp:
                if resp.status == 200:
                    result["accessible"] = True
                    result["anonymous_auth"] = True
                    result["can_list_pods"] = True
        except urllib.error.HTTPError as e:
            if e.code == 401:
                result["accessible"] = True
                result["anonymous_auth"] = False
        except:
            pass
        
        return result
    
    def _check_kube_configs(self) -> List[str]:
        """Find accessible kubeconfig files"""
        found_configs = []
        
        for config_path in self.K8S_PATHS["kube_config"]:
            if self._file_exists(config_path) and self._file_readable(config_path):
                found_configs.append(config_path)
        
        return found_configs
    
    def scan(self) -> List[Finding]:
        """Scan for Kubernetes vulnerabilities"""
        
        # Check if we're in a Kubernetes pod
        if self.k8s_env:
            self.add_finding(Finding(
                module="kubernetes",
                title="Running in Kubernetes Pod",
                description="Container is running inside a Kubernetes pod",
                severity=Severity.INFO,
                exploitability=Exploitability.UNLIKELY,
                technical_details={"environment": self.k8s_env},
            ))
            
            # Check service account token
            if self.service_account_token:
                sa_perms = self._check_service_account_permissions()
                severity = Severity.INFO
                exploitability = Exploitability.POTENTIAL
                
                if sa_perms["can_list_pods"]:
                    severity = Severity.MEDIUM
                    exploitability = Exploitability.LIKELY
                
                if sa_perms["can_list_secrets"]:
                    severity = Severity.HIGH
                    exploitability = Exploitability.CONFIRMED
                
                self.add_finding(Finding(
                    module="kubernetes",
                    title="Service Account Token Available",
                    description="Container has a mounted service account token that can authenticate to the Kubernetes API.\n"
                               f"Namespace: {sa_perms.get('namespace', 'unknown')}\n"
                               f"Can list pods: {sa_perms['can_list_pods']}\n"
                               f"Can list secrets: {sa_perms['can_list_secrets']}",
                    severity=severity,
                    exploitability=exploitability,
                    technical_details={
                        "token_present": True,
                        "permissions": sa_perms
                    },
                    remediation="Use least privilege RBAC, consider disabling automountServiceAccountToken",
                    references=[
                        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"
                    ]
                ))
            
            # Check Kubelet API
            kubelet_check = self._check_kubelet_api()
            if kubelet_check["accessible"]:
                severity = Severity.CRITICAL if kubelet_check["anonymous_auth"] else Severity.HIGH
                
                self.add_finding(Finding(
                    module="kubernetes",
                    title="Kubelet API Accessible",
                    description=f"Container can reach the Kubelet API at port 10250.\n"
                               f"Anonymous auth: {kubelet_check['anonymous_auth']}\n"
                               f"Can list pods: {kubelet_check['can_list_pods']}",
                    severity=severity,
                    exploitability=Exploitability.CONFIRMED if kubelet_check["anonymous_auth"] else Exploitability.LIKELY,
                    technical_details=kubelet_check,
                    remediation="Enable Kubelet authentication and authorization, use network policies to restrict access",
                    references=[
                        "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/"
                    ]
                ))
        
        # Check for kubeconfig files
        kube_configs = self._check_kube_configs()
        if kube_configs:
            self.add_finding(Finding(
                module="kubernetes",
                title="Kubeconfig Files Found",
                description=f"Container has access to Kubernetes configuration files:\n" +
                           "\n".join(f"  • {cfg}" for cfg in kube_configs),
                severity=Severity.CRITICAL,
                exploitability=Exploitability.CONFIRMED,
                technical_details={"configs": kube_configs},
                remediation="Never store kubeconfig files in container images",
            ))
        
        # Check for common K8s tools
        k8s_tools = ["kubectl", "helm", "k9s", "kubectx", "kubens"]
        tools_found = []
        
        for tool in k8s_tools:
            result = self._run_command(["which", tool])
            if result and "not found" not in result:
                tools_found.append(tool)
        
        if tools_found:
            self.add_finding(Finding(
                module="kubernetes",
                title="Kubernetes CLI Tools Available",
                description=f"Kubernetes management tools found in container:\n" +
                           "\n".join(f"  • {tool}" for tool in tools_found),
                severity=Severity.MEDIUM,
                exploitability=Exploitability.POTENTIAL,
                technical_details={"tools": tools_found},
                remediation="Remove unnecessary Kubernetes CLI tools from production images",
            ))
        
        return self.findings
