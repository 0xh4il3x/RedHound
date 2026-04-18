#!/usr/bin/env python3
"""
Cloud metadata scanner - Harvests cloud credentials from metadata endpoints
"""

import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

from .base import BaseScanner, Finding, Severity, Exploitability


class CloudMetadataScanner(BaseScanner):
    """Scan for accessible cloud metadata endpoints"""
    
    METADATA_ENDPOINTS = {
        "aws": {
            "base": "http://169.254.169.254/latest/",
            "endpoints": [
                "meta-data/",
                "meta-data/iam/security-credentials/",
                "meta-data/iam/security-credentials/",
                "user-data/",
                "dynamic/instance-identity/document",
            ],
            "severity": Severity.CRITICAL,
        },
        "gcp": {
            "base": "http://metadata.google.internal/computeMetadata/v1/",
            "endpoints": [
                "instance/",
                "instance/service-accounts/",
                "instance/service-accounts/default/token",
                "project/",
            ],
            "headers": {"Metadata-Flavor": "Google"},
            "severity": Severity.CRITICAL,
        },
        "azure": {
            "base": "http://169.254.169.254/metadata/",
            "endpoints": [
                "instance?api-version=2021-02-01",
                "instance/compute?api-version=2021-02-01",
                "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            "headers": {"Metadata": "true"},
            "severity": Severity.CRITICAL,
        },
        "digitalocean": {
            "base": "http://169.254.169.254/metadata/v1/",
            "endpoints": [
                "id",
                "hostname",
                "user-data",
                "vendor-data",
            ],
            "severity": Severity.HIGH,
        },
        "openstack": {
            "base": "http://169.254.169.254/openstack/latest/",
            "endpoints": [
                "meta_data.json",
                "user_data",
            ],
            "severity": Severity.HIGH,
        },
        "oracle": {
            "base": "http://169.254.169.254/opc/v2/",
            "endpoints": [
                "instance/",
                "instance/metadata/",
                "vnics/",
            ],
            "severity": Severity.HIGH,
        },
        "alibaba": {
            "base": "http://100.100.100.200/latest/",
            "endpoints": [
                "meta-data/",
                "meta-data/ram/security-credentials/",
                "user-data/",
            ],
            "severity": Severity.HIGH,
        },
    }
    
    def __init__(self, verify_mode: bool = False):
        super().__init__(verify_mode)
        self.discovered_credentials = []
    
    def _make_request(self, url: str, headers: Optional[Dict] = None, timeout: int = 5) -> Optional[Dict]:
        """Make HTTP request to metadata endpoint"""
        try:
            req = urllib.request.Request(url)
            if headers:
                for key, value in headers.items():
                    req.add_header(key, value)
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = response.read().decode('utf-8')
                
                # Try to parse as JSON
                try:
                    return json.loads(data)
                except:
                    return {"raw": data}
        except Exception as e:
            return None
    
    def _check_aws_metadata(self) -> Dict[str, Any]:
        """Check AWS metadata service"""
        result = {
            "accessible": False,
            "credentials": None,
            "role": None,
            "user_data": None,
        }
        
        base = self.METADATA_ENDPOINTS["aws"]["base"]
        
        # Check if endpoint is reachable
        test = self._make_request(base + "meta-data/")
        if test:
            result["accessible"] = True
            
            # Try to get IAM role
            role_resp = self._make_request(base + "meta-data/iam/security-credentials/")
            if role_resp and "raw" in role_resp:
                role_name = role_resp["raw"].strip()
                if role_name:
                    result["role"] = role_name
                    # Try to get credentials
                    creds = self._make_request(
                        base + f"meta-data/iam/security-credentials/{role_name}"
                    )
                    if creds:
                        result["credentials"] = creds
            
            # Try to get user data
            user_data = self._make_request(base + "user-data/")
            if user_data:
                result["user_data"] = user_data
        
        return result
    
    def _check_gcp_metadata(self) -> Dict[str, Any]:
        """Check GCP metadata service"""
        result = {
            "accessible": False,
            "service_accounts": None,
            "token": None,
        }
        
        base = self.METADATA_ENDPOINTS["gcp"]["base"]
        headers = self.METADATA_ENDPOINTS["gcp"]["headers"]
        
        # Check if endpoint is reachable
        test = self._make_request(base + "instance/", headers)
        if test:
            result["accessible"] = True
            
            # Try to get service accounts
            sa_resp = self._make_request(base + "instance/service-accounts/", headers)
            if sa_resp and "raw" in sa_resp:
                result["service_accounts"] = sa_resp["raw"].strip()
                
                # Try to get token for default service account
                token = self._make_request(
                    base + "instance/service-accounts/default/token",
                    headers
                )
                if token:
                    result["token"] = token
        
        return result
    
    def _check_azure_metadata(self) -> Dict[str, Any]:
        """Check Azure metadata service"""
        result = {
            "accessible": False,
            "instance_info": None,
            "token": None,
        }
        
        base = self.METADATA_ENDPOINTS["azure"]["base"]
        headers = self.METADATA_ENDPOINTS["azure"]["headers"]
        
        # Check if endpoint is reachable
        test = self._make_request(base + "instance?api-version=2021-02-01", headers)
        if test:
            result["accessible"] = True
            result["instance_info"] = test
            
            # Try to get managed identity token
            token = self._make_request(
                base + "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                headers
            )
            if token:
                result["token"] = token
        
        return result
    
    def _verify_credential_usage(self, cloud: str, credentials: Dict) -> bool:
        """Verify credentials are usable (only in verify mode)"""
        if not self.verify_mode:
            return False
        
        # This would contain safe verification logic
        # For now, just check if we got actual credentials
        if cloud == "aws" and credentials.get("AccessKeyId"):
            return True
        elif cloud == "gcp" and credentials.get("access_token"):
            return True
        elif cloud == "azure" and credentials.get("access_token"):
            return True
        
        return False
    
    def scan(self) -> List[Finding]:
        """Scan for cloud metadata exposure"""
        
        # Check AWS
        aws_result = self._check_aws_metadata()
        if aws_result["accessible"]:
            exploitability = Exploitability.LIKELY
            if aws_result["credentials"]:
                if self._verify_credential_usage("aws", aws_result["credentials"]):
                    exploitability = Exploitability.CONFIRMED
            
            self.add_finding(Finding(
                module="cloud",
                title="AWS Metadata Service Accessible",
                description="Container can access AWS Instance Metadata Service (IMDS).\n"
                           f"IAM Role: {aws_result.get('role', 'None')}\n"
                           f"Credentials Available: {'Yes' if aws_result.get('credentials') else 'No'}",
                severity=Severity.CRITICAL,
                exploitability=exploitability,
                technical_details=aws_result,
                remediation="Use IMDSv2 with token requirement, block metadata endpoint at network level, or use IAM roles for service accounts (IRSA)",
                references=[
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
                ]
            ))
        
        # Check GCP
        gcp_result = self._check_gcp_metadata()
        if gcp_result["accessible"]:
            exploitability = Exploitability.LIKELY
            if gcp_result["token"]:
                if self._verify_credential_usage("gcp", gcp_result["token"]):
                    exploitability = Exploitability.CONFIRMED
            
            self.add_finding(Finding(
                module="cloud",
                title="GCP Metadata Service Accessible",
                description="Container can access GCP Metadata Service.\n"
                           f"Service Accounts: {gcp_result.get('service_accounts', 'None')}\n"
                           f"Token Available: {'Yes' if gcp_result.get('token') else 'No'}",
                severity=Severity.CRITICAL,
                exploitability=exploitability,
                technical_details=gcp_result,
                remediation="Enable Workload Identity, use GKE Metadata Concealment, or block metadata endpoint",
                references=[
                    "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity"
                ]
            ))
        
        # Check Azure
        azure_result = self._check_azure_metadata()
        if azure_result["accessible"]:
            exploitability = Exploitability.LIKELY
            if azure_result["token"]:
                if self._verify_credential_usage("azure", azure_result["token"]):
                    exploitability = Exploitability.CONFIRMED
            
            self.add_finding(Finding(
                module="cloud",
                title="Azure Metadata Service Accessible",
                description="Container can access Azure Instance Metadata Service (IMDS).\n"
                           f"Token Available: {'Yes' if azure_result.get('token') else 'No'}",
                severity=Severity.CRITICAL,
                exploitability=exploitability,
                technical_details=azure_result,
                remediation="Use Azure AD Pod Identity or Workload Identity, block metadata endpoint",
                references=[
                    "https://docs.microsoft.com/en-us/azure/aks/use-azure-ad-pod-identity"
                ]
            ))
        
        # Check other cloud providers
        for cloud in ["digitalocean", "openstack", "oracle", "alibaba"]:
            base = self.METADATA_ENDPOINTS[cloud]["base"]
            test = self._make_request(base)
            
            if test:
                self.add_finding(Finding(
                    module="cloud",
                    title=f"{cloud.title()} Metadata Service Accessible",
                    description=f"Container can access {cloud.title()} metadata service",
                    severity=self.METADATA_ENDPOINTS[cloud]["severity"],
                    exploitability=Exploitability.LIKELY,
                    technical_details={"response": test},
                    remediation=f"Block metadata endpoint for {cloud}",
                ))
        
        return self.findings
