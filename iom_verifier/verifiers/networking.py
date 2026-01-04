import socket
import re
from typing import Dict, Any, List
from .base import BaseVerifier, VerificationResult

class NetworkingVerifier(BaseVerifier):
    ids = [
        "AWS - Security Group allowing ingress to port 22",
        "AWS - Security Group allowing ingress to port 3389",
        "NLB/ALB global access configured to one or more administrative ports.",
        "NLB/ALB global access configured to one or more administrative ports",
        "ELB global access configured to one or more administrative ports",
        "NLB/ALB configured as publicly accessible on non-web ports.",
        "ELB configured as publicly accessible on non-web ports.",
        "MQ Broker is publicly accessible", # 5671/5672 or web console
        "AWS - RDS Instance is Publicly Accessible", # Default ports logic needed
        "AWS - Redshift Cluster is Publicly Accessible", # 5439
        "AWS - Elasticsearch Domain is Publicly Accessible", # 443/80
        "EKS node(s) are publicly accessible via inbound security group rule"
    ]
    
    # Mapping of service/IoM types to likely ports
    DEFAULT_PORTS = {
        "port 22": 22,
        "port 3389": 3389,
        "ssh": 22,
        "rdp": 3389,
        "rds": 3306, # Default MySQL, could be others but 3306/5432 common
        "redshift": 5439,
        "elasticsearch": 443,
        "mq": 5671, # AMQPS
        "nlb": 80, # Fallback
        "alb": 80, # Fallback
        "elb": 80 # Fallback
    }

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        rule_name = row.get('Rule Name', '').lower()
        resource_id = row.get('Resource ID', '')
        
        # 1. Determine Target Host
        target_host = self._extract_host(resource_id, row)
        if not target_host:
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message=f"Could not determine target hostname/IP from Resource ID: {resource_id}"
            )

        # 2. Determine Target Port
        target_port = self._determine_port(rule_name, row)
        if not target_port:
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message=f"Could not determine target port from Rule Name: {row.get('Rule Name')}"
            )
            
        # 3. Perform Check
        return self._check_connection(target_host, target_port)

    def _extract_host(self, resource_id: str, row: Dict[str, Any]) -> str:
        # If Resource ID looks like a domain or IP, use it.
        # Regex for IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        # Regex for generic domain (simplified)
        domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        
        if re.match(ip_pattern, resource_id) or re.match(domain_pattern, resource_id):
            return resource_id
            
        # Try to find something in Findings or Description? 
        # For now, if Resource ID isn't a host, we try to see if it's an ARN and if the last part is a DNS name (e.g. ELB)
        if resource_id.startswith("arn:"):
            name = resource_id.split("/")[-1]
            # Heuristic: if name looks like a DNS
            if "." in name: 
                return name
        
        # Fallback: Check 'Findings' column for text like "Public IP: x.x.x.x" (common in some tools)
        findings = row.get('Findings', '')
        # Simple extraction logic could go here
        
        return None

    def _determine_port(self, rule_name: str, row: Dict[str, Any]) -> int:
        for key, port in self.DEFAULT_PORTS.items():
            if key in rule_name:
                return port
        return None

    def _check_connection(self, host: str, port: int) -> VerificationResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0) # 3 seconds timeout
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Exploitable",
                    message=f"Connection to {host}:{port} succeeded. Port is OPEN."
                )
            else:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Secure",
                    message=f"Connection to {host}:{port} failed (Code: {result}). Port is CLOSED or FILTERED."
                )
        except Exception as e:
             return VerificationResult(
                execution_status="Executed",
                exploit_status="Error",
                message=f"Socket error connecting to {host}:{port}: {str(e)}"
            )
