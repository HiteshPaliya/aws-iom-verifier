from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class VerificationResult:
    execution_status: str  # "Executed", "Skipped", "Error"
    exploit_status: str    # "Exploitable", "Secure", "Unknown", "N/A"
    message: str           # Verbose details

class BaseVerifier(ABC):
    """
    Abstract Base Class for all IoM Verifiers.
    """
    
    # List of Rule Names or Violation Types this verifier supports
    ids: list[str] = []

    @abstractmethod
    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        """
        Performs the verification logic for a given CSV row.
        Returns a VerificationResult object.
        """
        pass
