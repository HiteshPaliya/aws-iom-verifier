from .s3 import S3Verifier
from .networking import NetworkingVerifier
from .services import ServicesVerifier
from .manual import ManualVerifier
from .azure_storage import AzureStorageVerifier
from .gcp_storage import GCPStorageVerifier

# Instantiate checks
ALL_VERIFIERS = [
    S3Verifier(),
    NetworkingVerifier(),
    ServicesVerifier(),
    ManualVerifier(),
    AzureStorageVerifier(),
    GCPStorageVerifier()
]
