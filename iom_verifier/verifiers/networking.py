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
        "MQ Broker is publicly accessible",
        "AWS - RDS Instance is Publicly Accessible",
        "AWS - Redshift Cluster is Publicly Accessible",
        "AWS - Elasticsearch Domain is Publicly Accessible",
        "EKS node(s) are publicly accessible via inbound security group rule",
        # Azure - Networking
        "Firewall instance TCP or UDP port 3389 is open to the public",
        "Firewall instance TCP/UDP port 3389 is open to the public",
        "Network Security Group rule allows ingress traffic from any source on high risk ports",
        "Firewall instance TCP port 2375 or 2376 is open to the public",
        "Firewall instance UDP port 137 or 138 is open to the public",
        "Network Security Group rule allows HTTP(S) access from any source",
        "Firewall instance TCP port 1433 or UDP port 1434 is open to the public",
        "SQL server configured with firewall rule to allow access from all networks",
        "Firewall instance TCP or UDP port 53 is open to the public",
        "Firewall instance UDP or TCP port 445 is open to the public",
        "Firewall instance UDP/TCP port 445 is open to the public",
        "Azure App Service web apps configured with public network access",
        "Azure App Service web application with public network access",
        "Azure Logic app configured as publicly accessible",
        "Firewall instance TCP port 135 is open to the public",
        "Virtual Machine allows public internet access via non-web ports while running",
        "Virtual Machine allows public internet access to non-web ports while running",
        "Firewall instance allow all source IPs to all destination IPs",
        "Cosmos DB allows traffic from public Azure datacenters",
        "Firewall instance TCP port 50070 and 50470 is open to the public",
        "Network Security Group rule allows ingress traffic from any source on port not commonly used",
        "Azure OpenAI service has public network access enabled",
        "OpenAI service public network access is enabled",
        "Firewall instance TCP port 4333 or 3306 is open to the public",
        "Firewall instance TCP port 5500 is open to the public",
        "Network Security Group rule allows SSH access from any source",
        "Network Security Group rule allows UDP access from any source",
        "Load Balancer rule allow high risk port",
        "Load Balancer rule allows inbound traffic from the internet on high risk ports",
        "Firewall instance TCP port 5900 is open to the public",
        "Network Security Group rule allows ingress traffic from any source on any protocol",
        "Firewall instance TCP port 23 is open to the public",
        "Firewall instance TCP port 20 or 21 is open to the public",
        "PostgreSQL Flexible Server allows access from all IPv4",
        "Firewall instance TCP port 22 is open to the public",
        "Firewall instance publicly configured allows global public IP in ingress rule(s) on non-web ports",
        "PostgreSQL Flexible Server allowing public network access",
        "PostgreSQL flex server public network access allowed",
        "Azure Container Apps environment configured with public access",
        "MySQL Flexible Server has public network access enabled",
        "MySQL database flexible server public network access is enabled",
        "PostgreSQL Flexible Server allowing public access from ANY Azure service",
        "Virtual Machine allows public internet access via SSH on port 22 while running",
        "Virtual Machine allows public internet access to SSH port 22 while running",
        "Firewall instance TCP port 1522 is open to the public",
        "Virtual Machine allows inbound traffic from the internet on a high risk port",
        "Virtual Machine allows inbound from any source in security group rules",
        "Network Security Group rule overly permissive to inbound traffic over any protocol and port",
        "Network Security Group rule overly permissive to inbound traffic over any protocol",
        "AKS authorized IP range is not configured.",
        "AKS authorized IP range is not configured",
        "Azure OpenAI service public network access should be restricted",
        "OpenAI service public network access should be restricted",
        "Virtual Machine allows inbound from internet on any port from any source",
        "Azure Machine Learning workspace configured with overly permissive network access",
        "Azure Machine Learning workspace with overly permissive network",
        "Network Security Group rule allows ingress traffic from any source on all ports",
        "Firewall instance TCP port 5601 is open to the public",
        "Cosmos DB account is configured with public access from all networks",
        "CosmosDB is configured with public access from all networks",
        "Virtual Machine allows public internet access via RDP on port 3389 while running",
        "Virtual Machine allows public internet access to RDP port 3389 while running",
        "Firewall instance TCP port 9200 is open to the public",
        "Firewall instance TCP port 8020 is open to the public",
        "Firewall instance TCP port 1521 is open to the public",
        "Virtual Machine allows public internet access to Docker (port 2375/2376)",
        "Virtual Machine allows inbound from any source on any protocol",
        "Firewall instance TCP port 5432 is open to the public",
        "Firewall instance TCP ports 4505 or 4506 are open to the public",
        "Network Security Group rule allows RDP access from any source",
        "Cosmos DB Account allows public network access without firewall rules",
        "CosmosDB account with public access has no firewall rules",
        "Firewall instance TCP port 25 is open to the public",
        "Azure Machine Learning compute instance configured with public IP",
        "Azure Machine Learning compute instance configured with public IP",
        "Azure Machine Learning compute instance with public IP",
        # GCP - Networking
        "Cloud SQL instance is open to public",
        "Cloud SQL PostgreSQL Instance IP assignment is not set to private",
        "Cloud SQL instance assigned public IP",
        "Compute Engine instance configured with public IP",
        "GKE Cluster inbound firewall rule allows all traffic"
    ]
    
    # Mapping of service/IoM types to likely ports
    DEFAULT_PORTS = {
        "port 22": 22,
        "port 3389": 3389,
        "port 2375": 2375,
        "port 2376": 2376,
        "port 137": 137,
        "port 138": 138,
        "port 1433": 1433,
        "port 1434": 1434,
        "port 53": 53,
        "port 445": 445,
        "port 135": 135,
        "port 50070": 50070,
        "port 50470": 50470,
        "port 4333": 4333,
        "port 3306": 3306,
        "port 5500": 5500,
        "port 5900": 5900,
        "port 23": 23,
        "port 20": 20,
        "port 21": 21,
        "port 1522": 1522,
        "port 5601": 5601,
        "port 9200": 9200,
        "port 8020": 8020,
        "port 1521": 1521,
        "port 5432": 5432,
        "port 4505": 4505,
        "port 4506": 4506,
        "port 25": 25,
        "ssh": 22,
        "rdp": 3389,
        "rds": 3306,
        "redshift": 5439,
        "elasticsearch": 443,
        "mq": 5671,
        "nlb": 80,
        "alb": 80,
        "elb": 80,
        "sql": 1433,
        "mysql": 3306,
        "postgresql": 5432,
        "http": 80,
        "https": 443,
        "ftp": 21,
        "telnet": 23,
        "dns": 53,
        "openai": 443,
        "cosmos": 443,
        "compute engine": 22, # Default to SSH for checking connectivity on generic VM rule
        "cloud sql": 5432 # Default to Postgres/MySQL check (5432 or 3306) - heuristic
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
        # Search for IP in findings
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", findings)
        if ip_match:
            return ip_match.group(0)
        
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
