"""Tests for the Merkle tree functionality."""

import pytest

from fastmcp.ledger.merkle import MerkleTree, MerkleProof, verify_merkle_proof


class TestMerkleTree:
    """Test the MerkleTree class."""
    
    def test_single_leaf(self):
        """Test Merkle tree with a single leaf."""
        leaf_hashes = ["hash1"]
        tree = MerkleTree(leaf_hashes)
        
        assert tree.get_root() == "hash1"
        assert tree.get_leaf_count() == 1
        assert tree.get_tree_height() == 1
    
    def test_two_leaves(self):
        """Test Merkle tree with two leaves."""
        leaf_hashes = ["hash1", "hash2"]
        tree = MerkleTree(leaf_hashes)
        
        # Root should be hash of concatenated leaves
        import hashlib
        expected_root = hashlib.sha256(("hash1" + "hash2").encode()).hexdigest()
        assert tree.get_root() == expected_root
        assert tree.get_leaf_count() == 2
        assert tree.get_tree_height() == 2
    
    def test_three_leaves(self):
        """Test Merkle tree with three leaves (odd number)."""
        leaf_hashes = ["hash1", "hash2", "hash3"]
        tree = MerkleTree(leaf_hashes)
        
        # With odd number of leaves, last leaf should be duplicated
        assert tree.get_leaf_count() == 3
        assert tree.get_tree_height() == 3
    
    def test_four_leaves(self):
        """Test Merkle tree with four leaves."""
        leaf_hashes = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaf_hashes)
        
        assert tree.get_leaf_count() == 4
        assert tree.get_tree_height() == 3
    
    def test_large_tree(self):
        """Test Merkle tree with many leaves."""
        leaf_hashes = [f"hash{i}" for i in range(100)]
        tree = MerkleTree(leaf_hashes)
        
        assert tree.get_leaf_count() == 100
        assert tree.get_tree_height() > 1
        assert tree.get_root() is not None
    
    def test_generate_proof_single_leaf(self):
        """Test proof generation for single leaf."""
        leaf_hashes = ["hash1"]
        tree = MerkleTree(leaf_hashes)
        
        proof = tree.generate_proof("hash1")
        assert proof is not None
        assert proof.leaf_hash == "hash1"
        assert proof.path == []
        assert proof.root_hash == "hash1"
        assert proof.verify() is True
    
    def test_generate_proof_two_leaves(self):
        """Test proof generation for two leaves."""
        leaf_hashes = ["hash1", "hash2"]
        tree = MerkleTree(leaf_hashes)
        
        # Proof for first leaf
        proof1 = tree.generate_proof("hash1")
        assert proof1 is not None
        assert proof1.leaf_hash == "hash1"
        assert len(proof1.path) == 1
        assert proof1.path[0]["hash"] == "hash2"
        assert proof1.path[0]["position"] == "right"
        assert proof1.verify() is True
        
        # Proof for second leaf
        proof2 = tree.generate_proof("hash2")
        assert proof2 is not None
        assert proof2.leaf_hash == "hash2"
        assert len(proof2.path) == 1
        assert proof2.path[0]["hash"] == "hash1"
        assert proof2.path[0]["position"] == "left"
        assert proof2.verify() is True
    
    def test_generate_proof_nonexistent_leaf(self):
        """Test proof generation for non-existent leaf."""
        leaf_hashes = ["hash1", "hash2"]
        tree = MerkleTree(leaf_hashes)
        
        proof = tree.generate_proof("nonexistent")
        assert proof is None
    
    def test_verify_leaf(self):
        """Test leaf verification."""
        leaf_hashes = ["hash1", "hash2", "hash3"]
        tree = MerkleTree(leaf_hashes)
        
        # Verify existing leaves
        assert tree.verify_leaf("hash1") is True
        assert tree.verify_leaf("hash2") is True
        assert tree.verify_leaf("hash3") is True
        
        # Verify non-existent leaf
        assert tree.verify_leaf("nonexistent") is False
    
    def test_verify_proof(self):
        """Test proof verification."""
        leaf_hashes = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaf_hashes)
        
        proof = tree.generate_proof("hash1")
        assert proof is not None
        assert tree.verify_proof(proof) is True
        
        # Tamper with proof
        proof.leaf_hash = "tampered"
        assert tree.verify_proof(proof) is False
    
    def test_to_dict_and_from_dict(self):
        """Test serialization and deserialization."""
        leaf_hashes = ["hash1", "hash2", "hash3"]
        tree1 = MerkleTree(leaf_hashes)
        
        # Convert to dict
        tree_dict = tree1.to_dict()
        assert "root_hash" in tree_dict
        assert "leaf_count" in tree_dict
        assert "tree_height" in tree_dict
        assert "tree_data" in tree_dict
        assert "leaf_hashes" in tree_dict
        
        # Convert back to tree
        tree2 = MerkleTree.from_dict(tree_dict)
        assert tree2.get_root() == tree1.get_root()
        assert tree2.get_leaf_count() == tree1.get_leaf_count()
        assert tree2.get_tree_height() == tree1.get_tree_height()
        assert tree2.get_leaf_hashes() == tree1.get_leaf_hashes()
    
    def test_empty_tree_raises_error(self):
        """Test that empty tree raises error."""
        with pytest.raises(ValueError, match="Cannot create Merkle tree with empty leaf list"):
            MerkleTree([])


class TestMerkleProof:
    """Test the MerkleProof class."""
    
    def test_proof_verification_simple(self):
        """Test simple proof verification."""
        import hashlib
        
        # Create a simple two-leaf tree
        leaf_hash = "hash1"
        sibling_hash = "hash2"
        combined = sibling_hash + leaf_hash  # sibling on left, leaf on right
        root_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            path=[{"hash": sibling_hash, "position": "left"}],
            root_hash=root_hash
        )
        
        assert proof.verify() is True
    
    def test_proof_verification_complex(self):
        """Test complex proof verification with multiple levels."""
        import hashlib
        
        # Create a more complex tree structure
        leaf_hash = "hash1"
        path = [
            {"hash": "hash2", "position": "right"},  # sibling at leaf level
            {"hash": "intermediate_hash", "position": "left"}  # sibling at parent level
        ]
        
        # Calculate expected root
        # First level: hash1 + hash2
        level1 = hashlib.sha256(("hash1" + "hash2").encode()).hexdigest()
        # Second level: intermediate_hash + level1
        root_hash = hashlib.sha256(("intermediate_hash" + level1).encode()).hexdigest()
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            path=path,
            root_hash=root_hash
        )
        
        assert proof.verify() is True
    
    def test_proof_verification_failure(self):
        """Test proof verification failure."""
        proof = MerkleProof(
            leaf_hash="hash1",
            path=[{"hash": "hash2", "position": "left"}],
            root_hash="wrong_root_hash"
        )
        
        assert proof.verify() is False


class TestVerifyMerkleProof:
    """Test the standalone verify_merkle_proof function."""
    
    def test_verify_merkle_proof_function(self):
        """Test the standalone verify_merkle_proof function."""
        import hashlib
        
        leaf_hash = "hash1"
        path = [{"hash": "hash2", "position": "left"}]
        # When sibling is on the left, we concatenate sibling + leaf
        combined = "hash2" + leaf_hash
        root_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        assert verify_merkle_proof(leaf_hash, path, root_hash) is True
        
        # Test with wrong root
        assert verify_merkle_proof(leaf_hash, path, "wrong_root") is False
    
    def test_verify_merkle_proof_empty_path(self):
        """Test verify_merkle_proof with empty path (single leaf)."""
        leaf_hash = "hash1"
        path = []
        root_hash = "hash1"  # For single leaf, root equals leaf
        
        assert verify_merkle_proof(leaf_hash, path, root_hash) is True
        assert verify_merkle_proof(leaf_hash, path, "wrong_root") is False
