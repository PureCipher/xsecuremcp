"""Policy decision result types."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Decision:
    """Result of a policy evaluation."""
    
    allow: bool
    """Whether the action is allowed."""
    
    obligations: List[Dict[str, Any]]
    """List of obligations that must be fulfilled."""
    
    reason: str
    """Human-readable reason for the decision."""
    
    proof: Optional[Dict[str, Any]] = None
    """Optional proof or evidence for the decision."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary for JSON serialization."""
        return {
            "allow": self.allow,
            "obligations": self.obligations,
            "reason": self.reason,
            "proof": self.proof,
        }
    
    @classmethod
    def allow_decision(
        cls, 
        reason: str = "Access granted", 
        obligations: Optional[List[Dict[str, Any]]] = None,
        proof: Optional[Dict[str, Any]] = None
    ) -> "Decision":
        """Create an allow decision."""
        return cls(
            allow=True,
            obligations=obligations or [],
            reason=reason,
            proof=proof,
        )
    
    @classmethod
    def deny_decision(
        cls, 
        reason: str = "Access denied", 
        obligations: Optional[List[Dict[str, Any]]] = None,
        proof: Optional[Dict[str, Any]] = None
    ) -> "Decision":
        """Create a deny decision."""
        return cls(
            allow=False,
            obligations=obligations or [],
            reason=reason,
            proof=proof,
        )
