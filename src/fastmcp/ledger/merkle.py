"""Merkle tree implementation for ledger integrity verification."""

import hashlib
from typing import List, Dict, Any, Optional


class MerkleProof:
    """A Merkle proof for verifying an entry's inclusion in a Merkle tree."""
    
    def __init__(self, leaf_hash: str, path: List[Dict[str, str]], root_hash: str):
        """Initialize a Merkle proof.
        
        Args:
            leaf_hash: Hash of the leaf node being proven
            path: List of path elements with 'hash' and 'position' ('left' or 'right')
            root_hash: The root hash of the Merkle tree
        """
        self.leaf_hash = leaf_hash
        self.path = path
        self.root_hash = root_hash
    
    def verify(self) -> bool:
        """Verify that this proof is valid.
        
        Returns:
            True if the proof is valid, False otherwise
        """
        current_hash = self.leaf_hash
        
        for path_element in self.path:
            sibling_hash = path_element['hash']
            position = path_element['position']
            
            if position == 'left':
                # Current hash is on the right, sibling on the left
                combined = sibling_hash + current_hash
            else:  # position == 'right'
                # Current hash is on the left, sibling on the right
                combined = current_hash + sibling_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == self.root_hash


class MerkleTree:
    """A Merkle tree for efficient integrity verification of multiple entries."""
    
    def __init__(self, leaf_hashes: List[str]):
        """Initialize a Merkle tree from a list of leaf hashes.
        
        Args:
            leaf_hashes: List of SHA-256 hashes of the leaf nodes
        """
        if not leaf_hashes:
            raise ValueError("Cannot create Merkle tree with empty leaf list")
        
        self.leaf_hashes = leaf_hashes.copy()
        self.tree_data = []
        self.root_hash = self._build_tree()
    
    def _build_tree(self) -> str:
        """Build the Merkle tree and return the root hash.
        
        Returns:
            The root hash of the Merkle tree
        """
        if len(self.leaf_hashes) == 1:
            return self.leaf_hashes[0]
        
        # Ensure we have an even number of leaves by duplicating the last one if necessary
        current_level = self.leaf_hashes.copy()
        tree_levels = [current_level.copy()]
        
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left_hash = current_level[i]
                right_hash = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                
                # Combine and hash
                combined = left_hash + right_hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent_hash)
            
            tree_levels.append(next_level.copy())
            current_level = next_level
        
        # Store tree data for proof generation
        self.tree_data = tree_levels
        return current_level[0]
    
    def get_root(self) -> str:
        """Get the root hash of the Merkle tree.
        
        Returns:
            The root hash
        """
        return self.root_hash
    
    def get_tree_data(self) -> List[List[str]]:
        """Get the complete tree data structure.
        
        Returns:
            List of levels, where each level is a list of hashes
        """
        return self.tree_data
    
    def generate_proof(self, leaf_hash: str) -> Optional[MerkleProof]:
        """Generate a Merkle proof for a specific leaf hash.
        
        Args:
            leaf_hash: The hash of the leaf to prove
            
        Returns:
            A MerkleProof object or None if the leaf is not found
        """
        try:
            leaf_index = self.leaf_hashes.index(leaf_hash)
        except ValueError:
            return None
        
        if len(self.leaf_hashes) == 1:
            # Single leaf case
            return MerkleProof(leaf_hash, [], self.root_hash)
        
        path = []
        current_index = leaf_index
        
        # Traverse up the tree
        for level in range(len(self.tree_data) - 1):
            current_level = self.tree_data[level]
            
            # Find sibling
            if current_index % 2 == 0:  # Even index, sibling is on the right
                sibling_index = current_index + 1
                position = 'right'
            else:  # Odd index, sibling is on the left
                sibling_index = current_index - 1
                position = 'left'
            
            # Add sibling to path if it exists
            if sibling_index < len(current_level):
                path.append({
                    'hash': current_level[sibling_index],
                    'position': position
                })
            
            # Move to parent level
            current_index = current_index // 2
        
        return MerkleProof(leaf_hash, path, self.root_hash)
    
    def verify_proof(self, proof: MerkleProof) -> bool:
        """Verify a Merkle proof.
        
        Args:
            proof: The MerkleProof to verify
            
        Returns:
            True if the proof is valid, False otherwise
        """
        return proof.verify()
    
    def verify_leaf(self, leaf_hash: str) -> bool:
        """Verify that a leaf hash is part of this Merkle tree.
        
        Args:
            leaf_hash: The leaf hash to verify
            
        Returns:
            True if the leaf is part of the tree, False otherwise
        """
        return leaf_hash in self.leaf_hashes
    
    def get_leaf_count(self) -> int:
        """Get the number of leaf nodes in the tree.
        
        Returns:
            The number of leaf nodes
        """
        return len(self.leaf_hashes)
    
    def get_leaf_hashes(self) -> List[str]:
        """Get the list of leaf hashes.
        
        Returns:
            List of leaf hashes
        """
        return self.leaf_hashes.copy()
    
    def get_tree_height(self) -> int:
        """Get the height of the Merkle tree.
        
        Returns:
            The height of the tree (number of levels)
        """
        return len(self.tree_data) if self.tree_data else 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the Merkle tree to a dictionary representation.
        
        Returns:
            Dictionary representation of the tree
        """
        return {
            "root_hash": self.root_hash,
            "leaf_count": self.get_leaf_count(),
            "tree_height": self.get_tree_height(),
            "tree_data": self.tree_data,
            "leaf_hashes": self.leaf_hashes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MerkleTree":
        """Create a MerkleTree from a dictionary representation.
        
        Args:
            data: Dictionary representation of the tree
            
        Returns:
            A MerkleTree instance
        """
        tree = cls(data["leaf_hashes"])
        tree.tree_data = data["tree_data"]
        tree.root_hash = data["root_hash"]
        return tree


def verify_merkle_proof(leaf_hash: str, proof_path: List[Dict[str, str]], root_hash: str) -> bool:
    """Verify a Merkle proof without creating a MerkleTree instance.
    
    Args:
        leaf_hash: Hash of the leaf being proven
        proof_path: List of path elements with 'hash' and 'position'
        root_hash: The expected root hash
        
    Returns:
        True if the proof is valid, False otherwise
    """
    proof = MerkleProof(leaf_hash, proof_path, root_hash)
    return proof.verify()
