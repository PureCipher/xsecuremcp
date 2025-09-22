"""Cryptographic utilities for contract signing and verification."""

import base64
from typing import Tuple

import nacl.encoding
import nacl.signing
from nacl.exceptions import BadSignatureError

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class CryptoError(Exception):
    """Cryptographic operation error."""
    pass


class Ed25519Signer:
    """Ed25519 signature operations for contract signing."""
    
    def __init__(self, private_key: bytes = None):
        """Initialize signer with optional private key.
        
        Args:
            private_key: Optional private key bytes. If None, generates new key pair.
        """
        if private_key is None:
            self._signing_key = nacl.signing.SigningKey.generate()
        else:
            self._signing_key = nacl.signing.SigningKey(private_key)
        
        self._verify_key = self._signing_key.verify_key
    
    @classmethod
    def from_private_key_b64(cls, private_key_b64: str) -> "Ed25519Signer":
        """Create signer from base64-encoded private key.
        
        Args:
            private_key_b64: Base64-encoded private key
            
        Returns:
            Ed25519Signer instance
        """
        try:
            private_key = base64.b64decode(private_key_b64)
            return cls(private_key)
        except Exception as e:
            raise CryptoError(f"Invalid private key format: {e}")
    
    @classmethod
    def from_public_key_b64(cls, public_key_b64: str) -> "Ed25519Signer":
        """Create signer from base64-encoded public key (verification only).
        
        Args:
            public_key_b64: Base64-encoded public key
            
        Returns:
            Ed25519Signer instance (verification only)
        """
        try:
            public_key = base64.b64decode(public_key_b64)
            verify_key = nacl.signing.VerifyKey(public_key)
            signer = cls.__new__(cls)
            signer._signing_key = None  # No private key for verification only
            signer._verify_key = verify_key
            return signer
        except Exception as e:
            raise CryptoError(f"Invalid public key format: {e}")
    
    def sign(self, message: str) -> str:
        """Sign a message.
        
        Args:
            message: Message to sign
            
        Returns:
            Base64-encoded signature
            
        Raises:
            CryptoError: If signing fails
        """
        if self._signing_key is None:
            raise CryptoError("Cannot sign: no private key available")
        
        try:
            message_bytes = message.encode('utf-8')
            signed = self._signing_key.sign(message_bytes)
            signature = signed.signature
            return base64.b64encode(signature).decode('ascii')
        except Exception as e:
            raise CryptoError(f"Signing failed: {e}")
    
    def verify(self, message: str, signature: str) -> bool:
        """Verify a signature.
        
        Args:
            message: Original message
            signature: Base64-encoded signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            message_bytes = message.encode('utf-8')
            signature_bytes = base64.b64decode(signature)
            self._verify_key.verify(message_bytes, signature_bytes)
            return True
        except (BadSignatureError, Exception) as e:
            logger.debug(f"Signature verification failed: {e}")
            return False
    
    def get_public_key_b64(self) -> str:
        """Get base64-encoded public key.
        
        Returns:
            Base64-encoded public key
        """
        return base64.b64encode(self._verify_key.encode()).decode('ascii')
    
    def get_private_key_b64(self) -> str:
        """Get base64-encoded private key.
        
        Returns:
            Base64-encoded private key
            
        Raises:
            CryptoError: If no private key available
        """
        if self._signing_key is None:
            raise CryptoError("No private key available")
        
        return base64.b64encode(self._signing_key.encode()).decode('ascii')
    
    def get_key_pair_b64(self) -> Tuple[str, str]:
        """Get both public and private keys as base64 strings.
        
        Returns:
            Tuple of (public_key_b64, private_key_b64)
            
        Raises:
            CryptoError: If no private key available
        """
        return self.get_public_key_b64(), self.get_private_key_b64()


class ContractSigner:
    """High-level contract signing operations."""
    
    def __init__(self, signer: Ed25519Signer):
        """Initialize with Ed25519 signer.
        
        Args:
            signer: Ed25519Signer instance
        """
        self._signer = signer
    
    def sign_contract(self, contract_id: str, content_hash: str, signer_id: str, signer_type: str) -> str:
        """Sign a contract.
        
        Args:
            contract_id: Contract ID
            content_hash: SHA-256 hash of contract content
            signer_id: ID of the signing party
            signer_type: Type of signer (e.g., 'provider', 'payor', 'patient')
            
        Returns:
            Base64-encoded signature
            
        Raises:
            CryptoError: If signing fails
        """
        # Create signing message
        signing_message = f"{contract_id}:{content_hash}:{signer_id}:{signer_type}"
        return self._signer.sign(signing_message)
    
    def verify_contract_signature(self, contract_id: str, content_hash: str, signer_id: str, 
                                signer_type: str, signature: str) -> bool:
        """Verify a contract signature.
        
        Args:
            contract_id: Contract ID
            content_hash: SHA-256 hash of contract content
            signer_id: ID of the signing party
            signer_type: Type of signer
            signature: Base64-encoded signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        # Create signing message
        signing_message = f"{contract_id}:{content_hash}:{signer_id}:{signer_type}"
        return self._signer.verify(signing_message, signature)
    
    def get_public_key_b64(self) -> str:
        """Get base64-encoded public key."""
        return self._signer.get_public_key_b64()
    
    def get_private_key_b64(self) -> str:
        """Get base64-encoded private key."""
        return self._signer.get_private_key_b64()


def generate_key_pair() -> Tuple[str, str]:
    """Generate a new Ed25519 key pair.
    
    Returns:
        Tuple of (public_key_b64, private_key_b64)
    """
    signer = Ed25519Signer()
    return signer.get_key_pair_b64()


def verify_signature(public_key_b64: str, message: str, signature: str) -> bool:
    """Verify a signature with a public key.
    
    Args:
        public_key_b64: Base64-encoded public key
        message: Original message
        signature: Base64-encoded signature
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signer = Ed25519Signer.from_public_key_b64(public_key_b64)
        return signer.verify(message, signature)
    except CryptoError:
        return False
