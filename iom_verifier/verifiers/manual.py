from typing import Dict, Any
from .base import BaseVerifier, VerificationResult

class ManualVerifier(BaseVerifier):
    ids = [
        "EMR cluster security group allows all traffic on port 8088",
        "API Gateway method does not require authorization or api key",
        "MSK Cluster configured for public accessibility",
        "MSK Cluster should not be publicly accessible",
        "AWS OpenSearch Domain policy is overly permissive",
        "OpenSearch Domain policy should not be overly permissive",
        "EKS cluster with open VPC CIDR range for public access",
        "NLB/ALB configured as publicly accessible on non-web ports",
        "SageMaker Domain not configured for VPC Only Traffic",
        "S3 bucket policy allows public access to CloudTrail logs",
        "Lambda Function is Configured to be publicly accessible",
        "EKS cluster VPC endpoint access is publicly enabled",
        "AWS EventBridge EventBus exposed to the public",
        "SageMaker Notebook instance configured with Direct Internet Access",
        "AWS OpenSearch Domain allows anonymous access",
        "OpenSearch Domain should not allow anonymous access",
        "EKS Cluster endpoint access should not allow all IP addresses",
        "ELB configured as publicly accessible on non-web ports",
        "NLB configured with listener over high-risk ports with target groups over ports.",
        "NLB configured with listener over high-risk ports with target groups over ports",
        "API Gateway is accessible through public API endpoints",
        "SageMaker Notebook instance is not placed in vpc",
        "SageMaker Notebook instance not placed in vpc",
        "AWS Network Firewall without stateless rule group",
        "Network Firewall without stateless rule group",
        # GCP - Manual
        "BigQuery policy configured with 'allUsers' access",
        "GKE Cluster has the User 'allAuthenticatedUsers' Added as a Container Admin or Cluster Admin",
        "GKE Cluster has the user allAuthenticatedUsers added as a container admin or cluster admin",
        "KMS Cryptokey configured with 'allAuthenticatedUsers' access",
        "KMS crypto key configured with 'allAuthenticatedUsers' access",
        "BigQuery policy configured with 'allAuthenticatedUsers' access",
        "KMS policy binding roles overly permissive",
        "Cloud Storage uniform bucket-level access is disabled",
        "Compute Image configured with 'allAuthenticatedUsers' access",
        "KMS Cryptokey configured with 'allUsers' access",
        "KMS crypto key configured with 'allUsers' access"
    ]

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        return VerificationResult(
            execution_status="Skipped",
            exploit_status="Manual Check Required",
            message="Manual Check Required"
        )
