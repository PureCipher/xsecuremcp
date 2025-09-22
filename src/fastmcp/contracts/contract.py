"""Contract models and schemas for inter-agent contract management."""

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator
from sqlmodel import SQLModel, Field as SQLField, Relationship


class ContractState(str, Enum):
    """Contract lifecycle states."""
    DRAFT = "draft"
    PROPOSED = "proposed"
    SIGNED = "signed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Clause(BaseModel):
    """A contract clause with structured content."""
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(..., description="Clause title")
    content: str = Field(..., description="Clause content")
    type: str = Field(default="general", description="Clause type (e.g., 'hipaa', 'data_handling')")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional clause metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class Signature(BaseModel):
    """Cryptographic signature for contract verification."""
    
    signer_id: str = Field(..., description="ID of the signing party")
    signer_type: str = Field(..., description="Type of signer (e.g., 'provider', 'payor', 'patient')")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature")
    public_key: str = Field(..., description="Base64-encoded public key")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def model_dump(self, **kwargs):
        """Override model_dump to handle datetime serialization."""
        data = super().model_dump(**kwargs)
        # Convert datetime objects to ISO format strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


class Contract(SQLModel, table=True):
    """Contract model with SQLModel persistence."""
    
    __tablename__ = "contracts"
    
    # Primary fields
    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    title: str = SQLField(..., description="Contract title")
    description: str = SQLField(..., description="Contract description")
    
    # Contract content
    clauses: str = SQLField(..., description="JSON-encoded clauses")
    parties: str = SQLField(..., description="JSON-encoded parties")
    
    # Lifecycle
    state: ContractState = SQLField(default=ContractState.DRAFT)
    created_at: datetime = SQLField(default_factory=datetime.utcnow)
    proposed_at: Optional[datetime] = SQLField(default=None)
    signed_at: Optional[datetime] = SQLField(default=None)
    revoked_at: Optional[datetime] = SQLField(default=None)
    expires_at: Optional[datetime] = SQLField(default=None)
    
    # Signatures
    signatures: str = SQLField(default="[]", description="JSON-encoded signatures")
    
    # HIPAA compliance
    is_hipaa_compliant: bool = SQLField(default=False)
    hipaa_entities: str = SQLField(default="[]", description="JSON-encoded HIPAA entities")
    
    # Metadata
    contract_metadata: str = SQLField(default="{}", description="JSON-encoded metadata")
    version: str = SQLField(default="1.0.0")
    
    # Audit trail
    created_by: str = SQLField(..., description="ID of the creating party")
    last_modified: datetime = SQLField(default_factory=datetime.utcnow)
    
    def get_clauses(self) -> List[Clause]:
        """Get parsed clauses from JSON."""
        try:
            clauses_data = json.loads(self.clauses)
            return [Clause(**clause) for clause in clauses_data]
        except (json.JSONDecodeError, ValueError):
            return []
    
    def set_clauses(self, clauses: List[Clause]) -> None:
        """Set clauses as JSON."""
        self.clauses = json.dumps([clause.model_dump() for clause in clauses])
    
    def get_parties(self) -> List[Dict[str, Any]]:
        """Get parsed parties from JSON."""
        try:
            return json.loads(self.parties)
        except json.JSONDecodeError:
            return []
    
    def set_parties(self, parties: List[Dict[str, Any]]) -> None:
        """Set parties as JSON."""
        self.parties = json.dumps(parties)
    
    def get_signatures(self) -> List[Signature]:
        """Get parsed signatures from JSON."""
        try:
            signatures_data = json.loads(self.signatures)
            return [Signature(**sig) for sig in signatures_data]
        except (json.JSONDecodeError, ValueError):
            return []
    
    def set_signatures(self, signatures: List[Signature]) -> None:
        """Set signatures as JSON."""
        self.signatures = json.dumps([sig.model_dump() for sig in signatures])
    
    def get_hipaa_entities(self) -> List[Dict[str, Any]]:
        """Get parsed HIPAA entities from JSON."""
        try:
            return json.loads(self.hipaa_entities)
        except json.JSONDecodeError:
            return []
    
    def set_hipaa_entities(self, entities: List[Dict[str, Any]]) -> None:
        """Set HIPAA entities as JSON."""
        self.hipaa_entities = json.dumps(entities)
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get parsed metadata from JSON."""
        try:
            return json.loads(self.contract_metadata)
        except json.JSONDecodeError:
            return {}
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """Set metadata as JSON."""
        self.contract_metadata = json.dumps(metadata)
    
    def get_content_hash(self) -> str:
        """Get SHA-256 hash of contract content for signing."""
        content = {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "clauses": self.clauses,
            "parties": self.parties,
            "version": self.version
        }
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def can_transition_to(self, new_state: ContractState) -> bool:
        """Check if contract can transition to new state."""
        valid_transitions = {
            ContractState.DRAFT: [ContractState.PROPOSED, ContractState.REVOKED],
            ContractState.PROPOSED: [ContractState.SIGNED, ContractState.REVOKED, ContractState.DRAFT],
            ContractState.SIGNED: [ContractState.REVOKED],
            ContractState.REVOKED: [],  # Terminal state
            ContractState.EXPIRED: []   # Terminal state
        }
        return new_state in valid_transitions.get(self.state, [])
    
    def is_fully_signed(self) -> bool:
        """Check if contract is fully signed by all required parties."""
        parties = self.get_parties()
        signatures = self.get_signatures()
        
        # Check if all parties have signed
        signed_party_ids = {sig.signer_id for sig in signatures}
        required_party_ids = {party["id"] for party in parties}
        
        return required_party_ids.issubset(signed_party_ids)
    
    def get_unsigned_parties(self) -> List[Dict[str, Any]]:
        """Get parties that haven't signed yet."""
        parties = self.get_parties()
        signatures = self.get_signatures()
        signed_party_ids = {sig.signer_id for sig in signatures}
        
        return [party for party in parties if party["id"] not in signed_party_ids]


class ContractCreateRequest(BaseModel):
    """Request model for creating a contract."""
    
    title: str = Field(..., description="Contract title")
    description: str = Field(..., description="Contract description")
    clauses: List[Clause] = Field(..., description="Contract clauses")
    parties: List[Dict[str, Any]] = Field(..., description="Contract parties")
    is_hipaa_compliant: bool = Field(default=False, description="HIPAA compliance flag")
    hipaa_entities: Optional[List[Dict[str, Any]]] = Field(default=None, description="HIPAA entities")
    expires_at: Optional[datetime] = Field(default=None, description="Contract expiration")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    version: str = Field(default="1.0.0", description="Contract version")


class ContractProposeRequest(BaseModel):
    """Request model for proposing a contract."""
    
    proposed_to: List[str] = Field(..., description="IDs of parties to propose to")
    message: Optional[str] = Field(default=None, description="Proposal message")


class ContractSignRequest(BaseModel):
    """Request model for signing a contract."""
    
    signer_id: str = Field(..., description="ID of the signing party")
    signer_type: str = Field(..., description="Type of signer")
    public_key: str = Field(..., description="Base64-encoded public key")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Signature metadata")


class ContractRevokeRequest(BaseModel):
    """Request model for revoking a contract."""
    
    reason: str = Field(..., description="Reason for revocation")
    revoked_by: str = Field(..., description="ID of the revoking party")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Revocation metadata")


class ContractResponse(BaseModel):
    """Response model for contract operations."""
    
    id: str
    title: str
    description: str
    clauses: List[Clause]
    parties: List[Dict[str, Any]]
    state: ContractState
    created_at: datetime
    proposed_at: Optional[datetime]
    signed_at: Optional[datetime]
    revoked_at: Optional[datetime]
    expires_at: Optional[datetime]
    signatures: List[Dict[str, Any]]
    is_hipaa_compliant: bool
    hipaa_entities: List[Dict[str, Any]]
    contract_metadata: Dict[str, Any]
    version: str
    created_by: str
    last_modified: datetime
    content_hash: str
    is_fully_signed: bool
    unsigned_parties: List[Dict[str, Any]]
    
    def model_dump(self, **kwargs):
        """Override model_dump to handle datetime serialization."""
        data = super().model_dump(**kwargs)
        # Convert datetime objects to ISO format strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif key == "signatures" and isinstance(value, list):
                # Handle nested Signature objects
                data[key] = [sig.model_dump() if hasattr(sig, 'model_dump') else sig for sig in value]
        return data
    
    @classmethod
    def from_contract(cls, contract: Contract) -> "ContractResponse":
        """Create response from contract model."""
        # Pre-serialize signatures to handle datetime fields
        signatures = contract.get_signatures()
        serialized_signatures = [sig.model_dump() for sig in signatures]
        
        return cls(
            id=str(contract.id),  # Convert UUID to string
            title=contract.title,
            description=contract.description,
            clauses=contract.get_clauses(),
            parties=contract.get_parties(),
            state=contract.state,
            created_at=contract.created_at,
            proposed_at=contract.proposed_at,
            signed_at=contract.signed_at,
            revoked_at=contract.revoked_at,
            expires_at=contract.expires_at,
            signatures=serialized_signatures,  # Use pre-serialized signatures
            is_hipaa_compliant=contract.is_hipaa_compliant,
            hipaa_entities=contract.get_hipaa_entities(),
            contract_metadata=contract.get_metadata(),
            version=contract.version,
            created_by=contract.created_by,
            last_modified=contract.last_modified,
            content_hash=contract.get_content_hash(),
            is_fully_signed=contract.is_fully_signed(),
            unsigned_parties=contract.get_unsigned_parties()
        )
