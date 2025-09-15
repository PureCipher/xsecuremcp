"""Monitoring components for the reflexive core."""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict, deque

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class PolicyMonitor:
    """Monitor for policy violations."""
    
    def __init__(self, policy_engine=None):
        """Initialize the policy monitor.
        
        Args:
            policy_engine: Policy engine instance to monitor
        """
        self.policy_engine = policy_engine
        self.violation_history = deque(maxlen=1000)  # Keep last 1000 violations
        self.actor_violations = defaultdict(int)  # Track violations per actor
        
    async def __call__(self, action_context) -> Optional[Dict[str, Any]]:
        """Monitor an action for policy violations."""
        try:
            # Check for policy violations (works with or without policy engine)
            violations = await self._check_policy_violations(action_context)
            
            if violations:
                # Record violation
                violation_record = {
                    "type": "violation",
                    "severity": self._assess_violation_severity(violations),
                    "violations": violations,
                    "actor_id": action_context.actor_id,
                    "action_id": action_context.action_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                self.violation_history.append(violation_record)
                self.actor_violations[action_context.actor_id] += 1
                
                return violation_record
            
            return None
            
        except Exception as e:
            logger.error(f"Policy monitor error: {e}")
            return None
    
    async def _check_policy_violations(self, action_context) -> List[Dict[str, Any]]:
        """Check for policy violations in an action."""
        violations = []
        
        try:
            # Simulate policy checking
            # In a real implementation, this would use the actual policy engine
            
            # Check for suspicious patterns
            if action_context.action_type == "admin_access" and action_context.actor_id.startswith("guest"):
                violations.append({
                    "rule": "admin_access_restriction",
                    "message": "Guest user attempting admin access",
                    "severity": "high"
                })
            
            # Check for rate limiting
            recent_violations = [v for v in self.violation_history 
                               if v.get("actor_id") == action_context.actor_id 
                               and datetime.fromisoformat(v["timestamp"]) > datetime.utcnow() - timedelta(minutes=5)]
            
            if len(recent_violations) >= 3:
                violations.append({
                    "rule": "rate_limit_exceeded",
                    "message": f"Actor {action_context.actor_id} has {len(recent_violations)} recent violations",
                    "severity": "medium"
                })
            
            # Check for resource access patterns
            if action_context.resource_id and "sensitive" in action_context.resource_id.lower():
                if not action_context.metadata.get("authorized"):
                    violations.append({
                        "rule": "unauthorized_sensitive_access",
                        "message": "Unauthorized access to sensitive resource",
                        "severity": "critical"
                    })
            
        except Exception as e:
            logger.error(f"Error checking policy violations: {e}")
        
        return violations
    
    def _assess_violation_severity(self, violations: List[Dict[str, Any]]) -> str:
        """Assess the overall severity of violations."""
        if not violations:
            return "low"
        
        severities = [v.get("severity", "low") for v in violations]
        
        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        else:
            return "low"
    
    def get_violation_stats(self) -> Dict[str, Any]:
        """Get violation statistics."""
        return {
            "total_violations": len(self.violation_history),
            "actor_violations": dict(self.actor_violations),
            "recent_violations": len([v for v in self.violation_history 
                                    if datetime.fromisoformat(v["timestamp"]) > datetime.utcnow() - timedelta(hours=1)])
        }


class LedgerMonitor:
    """Monitor for ledger inconsistencies and anomalies."""
    
    def __init__(self, ledger=None):
        """Initialize the ledger monitor.
        
        Args:
            ledger: Provenance ledger instance to monitor
        """
        self.ledger = ledger
        self.integrity_checks = deque(maxlen=100)  # Keep last 100 integrity checks
        
    async def __call__(self, action_context) -> Optional[Dict[str, Any]]:
        """Monitor ledger for inconsistencies."""
        try:
            if not self.ledger:
                return None
            
            # Check ledger integrity
            integrity_issues = await self._check_ledger_integrity()
            
            if integrity_issues:
                # Record integrity issue
                issue_record = {
                    "type": "anomaly",
                    "severity": self._assess_integrity_severity(integrity_issues),
                    "issues": integrity_issues,
                    "action_id": action_context.action_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                self.integrity_checks.append(issue_record)
                return issue_record
            
            return None
            
        except Exception as e:
            logger.error(f"Ledger monitor error: {e}")
            return None
    
    async def _check_ledger_integrity(self) -> List[Dict[str, Any]]:
        """Check ledger for integrity issues."""
        issues = []
        
        try:
            # Check chain integrity
            is_valid = self.ledger.verify_chain_integrity()
            if not is_valid:
                issues.append({
                    "type": "chain_integrity",
                    "message": "Ledger chain integrity verification failed",
                    "severity": "critical"
                })
            
            # Check for missing blocks
            stats = self.ledger.get_ledger_statistics()
            if stats.get("total_entries", 0) > 0 and stats.get("total_blocks", 0) == 0:
                issues.append({
                    "type": "missing_blocks",
                    "message": "Entries exist but no blocks found",
                    "severity": "high"
                })
            
            # Check for unsealed blocks
            # This would require additional ledger methods to check for unsealed blocks
            
        except Exception as e:
            logger.error(f"Error checking ledger integrity: {e}")
            issues.append({
                "type": "integrity_check_error",
                "message": f"Error during integrity check: {str(e)}",
                "severity": "medium"
            })
        
        return issues
    
    def _assess_integrity_severity(self, issues: List[Dict[str, Any]]) -> str:
        """Assess the overall severity of integrity issues."""
        if not issues:
            return "low"
        
        severities = [i.get("severity", "low") for i in issues]
        
        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        else:
            return "low"
    
    def get_integrity_stats(self) -> Dict[str, Any]:
        """Get integrity check statistics."""
        return {
            "total_checks": len(self.integrity_checks),
            "recent_issues": len([i for i in self.integrity_checks 
                                if datetime.fromisoformat(i["timestamp"]) > datetime.utcnow() - timedelta(hours=1)])
        }


class AnomalyDetector:
    """Detector for behavioral anomalies."""
    
    def __init__(self):
        """Initialize the anomaly detector."""
        self.actor_patterns = defaultdict(lambda: {
            "action_counts": defaultdict(int),
            "resource_access": defaultdict(int),
            "session_times": deque(maxlen=100),
            "last_seen": None
        })
        self.global_patterns = {
            "action_frequency": defaultdict(int),
            "resource_access": defaultdict(int),
            "time_patterns": defaultdict(int)
        }
        
    async def __call__(self, action_context) -> Optional[Dict[str, Any]]:
        """Detect anomalies in an action."""
        try:
            # Update patterns
            self._update_patterns(action_context)
            
            # Detect anomalies
            anomalies = await self._detect_anomalies(action_context)
            
            if anomalies:
                return {
                    "type": "anomaly",
                    "severity": self._assess_anomaly_severity(anomalies),
                    "anomalies": anomalies,
                    "actor_id": action_context.actor_id,
                    "action_id": action_context.action_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Anomaly detector error: {e}")
            return None
    
    def _update_patterns(self, action_context):
        """Update behavioral patterns."""
        actor_id = action_context.actor_id
        actor_data = self.actor_patterns[actor_id]
        
        # Update action counts
        actor_data["action_counts"][action_context.action_type] += 1
        self.global_patterns["action_frequency"][action_context.action_type] += 1
        
        # Update resource access
        if action_context.resource_id:
            actor_data["resource_access"][action_context.resource_id] += 1
            self.global_patterns["resource_access"][action_context.resource_id] += 1
        
        # Update session times
        actor_data["session_times"].append(action_context.timestamp)
        actor_data["last_seen"] = action_context.timestamp
        
        # Update time patterns
        hour = action_context.timestamp.hour
        self.global_patterns["time_patterns"][hour] += 1
    
    async def _detect_anomalies(self, action_context) -> List[Dict[str, Any]]:
        """Detect anomalies in the action."""
        anomalies = []
        actor_id = action_context.actor_id
        actor_data = self.actor_patterns[actor_id]
        
        # Check for unusual action frequency
        if len(actor_data["session_times"]) >= 10:
            recent_actions = [t for t in actor_data["session_times"] 
                            if t > datetime.utcnow() - timedelta(minutes=5)]
            if len(recent_actions) > 20:  # More than 20 actions in 5 minutes
                anomalies.append({
                    "type": "high_frequency",
                    "message": f"Actor {actor_id} performing {len(recent_actions)} actions in 5 minutes",
                    "severity": "medium"
                })
        
        # Check for unusual time patterns
        current_hour = action_context.timestamp.hour
        if current_hour < 6 or current_hour > 22:  # Unusual hours
            if actor_data["action_counts"].get(action_context.action_type, 0) < 5:  # New action type
                anomalies.append({
                    "type": "unusual_timing",
                    "message": f"Actor {actor_id} performing {action_context.action_type} at unusual hour {current_hour}",
                    "severity": "low"
                })
        
        # Check for new resource access
        if action_context.resource_id:
            if actor_data["resource_access"].get(action_context.resource_id, 0) == 1:
                # First time accessing this resource
                anomalies.append({
                    "type": "new_resource_access",
                    "message": f"Actor {actor_id} accessing new resource {action_context.resource_id}",
                    "severity": "low"
                })
        
        # Check for privilege escalation patterns
        if action_context.action_type in ["admin_access", "root_access", "privilege_escalation"]:
            if actor_data["action_counts"].get(action_context.action_type, 0) == 1:
                # First time performing privileged action
                anomalies.append({
                    "type": "privilege_escalation",
                    "message": f"Actor {actor_id} attempting privileged action for first time",
                    "severity": "high"
                })
        
        return anomalies
    
    def _assess_anomaly_severity(self, anomalies: List[Dict[str, Any]]) -> str:
        """Assess the overall severity of anomalies."""
        if not anomalies:
            return "low"
        
        severities = [a.get("severity", "low") for a in anomalies]
        
        if "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        else:
            return "low"
    
    def get_anomaly_stats(self) -> Dict[str, Any]:
        """Get anomaly detection statistics."""
        return {
            "tracked_actors": len(self.actor_patterns),
            "global_action_types": len(self.global_patterns["action_frequency"]),
            "global_resources": len(self.global_patterns["resource_access"])
        }
