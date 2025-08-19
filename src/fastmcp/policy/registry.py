"""Policy registry for managing policies at runtime."""

import importlib
import importlib.metadata
import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from fastmcp.utilities.logging import get_logger

from .policy import Policy

logger = get_logger(__name__)


class PolicyRegistry:
    """Registry for managing policies at runtime."""
    
    def __init__(self):
        self._policies: Dict[str, Policy] = {}
        self._policy_classes: Dict[str, Type[Policy]] = {}
    
    def register_policy(self, policy: Policy) -> None:
        """Register a policy instance.
        
        Args:
            policy: The policy instance to register
        """
        self._policies[policy.name] = policy
        logger.info(f"Registered policy: {policy.name} v{policy.version}")
    
    def unregister_policy(self, name: str) -> Optional[Policy]:
        """Unregister a policy by name.
        
        Args:
            name: The name of the policy to unregister
            
        Returns:
            The unregistered policy, or None if not found
        """
        policy = self._policies.pop(name, None)
        if policy:
            logger.info(f"Unregistered policy: {name}")
        return policy
    
    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a policy by name.
        
        Args:
            name: The name of the policy
            
        Returns:
            The policy instance, or None if not found
        """
        return self._policies.get(name)
    
    def list_policies(self) -> List[Dict[str, Any]]:
        """List all registered policies.
        
        Returns:
            List of policy metadata dictionaries
        """
        return [policy.get_metadata() for policy in self._policies.values()]
    
    def load_policy_from_entry_point(self, entry_point_name: str) -> None:
        """Load policies from entry points.
        
        Args:
            entry_point_name: The entry point name to load from
        """
        try:
            entry_points = importlib.metadata.entry_points()
            if hasattr(entry_points, 'select'):
                # Python 3.10+
                policy_entry_points = entry_points.select(group=entry_point_name)
            else:
                # Python 3.8-3.9
                policy_entry_points = entry_points.get(entry_point_name, [])
            
            for entry_point in policy_entry_points:
                try:
                    policy_class = entry_point.load()
                    if issubclass(policy_class, Policy):
                        # Create policy with default name from entry point
                        policy = policy_class(name=entry_point.name)
                        self.register_policy(policy)
                    else:
                        logger.warning(f"Entry point {entry_point.name} does not return a Policy class")
                except Exception as e:
                    logger.error(f"Failed to load policy from entry point {entry_point.name}: {e}")
        except Exception as e:
            logger.error(f"Failed to load policies from entry points: {e}")
    
    def load_policies_from_yaml(self, yaml_path: Path) -> None:
        """Load policies from a YAML specification file.
        
        Args:
            yaml_path: Path to the YAML file
        """
        try:
            with open(yaml_path, 'r') as f:
                config = yaml.safe_load(f)
            
            policies_config = config.get('policies', [])
            for policy_config in policies_config:
                try:
                    policy_name = policy_config['name']
                    policy_type = policy_config['type']
                    policy_params = policy_config.get('parameters', {})
                    
                    # Get the policy class
                    policy_class = self._policy_classes.get(policy_type)
                    if not policy_class:
                        logger.error(f"Unknown policy type: {policy_type}")
                        continue
                    
                    # Create and register the policy
                    policy = policy_class(name=policy_name, **policy_params)
                    self.register_policy(policy)
                    
                except KeyError as e:
                    logger.error(f"Missing required field in policy config: {e}")
                except Exception as e:
                    logger.error(f"Failed to load policy from config: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to load policies from YAML file {yaml_path}: {e}")
    
    def register_policy_class(self, name: str, policy_class: Type[Policy]) -> None:
        """Register a policy class for dynamic instantiation.
        
        Args:
            name: The name to register the policy class under
            policy_class: The policy class to register
        """
        if not issubclass(policy_class, Policy):
            raise ValueError(f"Class {policy_class} must inherit from Policy")
        
        self._policy_classes[name] = policy_class
        logger.info(f"Registered policy class: {name}")
    
    def create_policy_from_config(self, config: Dict[str, Any]) -> Optional[Policy]:
        """Create a policy instance from configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            The created policy instance, or None if creation failed
        """
        try:
            policy_type = config.get('type')
            if not policy_type:
                logger.error("Policy config missing 'type' field")
                return None
            
            policy_class = self._policy_classes.get(policy_type)
            if not policy_class:
                logger.error(f"Unknown policy type: {policy_type}")
                return None
            
            policy_params = config.get('parameters', {})
            policy = policy_class(**policy_params)
            return policy
            
        except Exception as e:
            logger.error(f"Failed to create policy from config: {e}")
            return None
    
    def hot_reload_policies(self, yaml_path: Path) -> None:
        """Hot reload policies from YAML file.
        
        Args:
            yaml_path: Path to the YAML file
        """
        logger.info(f"Hot reloading policies from {yaml_path}")
        
        # Clear existing policies
        self._policies.clear()
        
        # Reload from entry points
        self.load_policy_from_entry_point("fastmcp.policies")
        
        # Reload from YAML
        if yaml_path.exists():
            self.load_policies_from_yaml(yaml_path)
        
        logger.info(f"Hot reload complete. {len(self._policies)} policies loaded")
