"""Example usage of the Reflexive Core."""

import asyncio
from datetime import datetime

from fastmcp import FastMCP
from fastmcp.reflexive import ReflexiveEngine, ActionContext, DecisionType, RiskLevel
from fastmcp.reflexive.monitor import PolicyMonitor, LedgerMonitor, AnomalyDetector
from fastmcp.reflexive.actions import ActionFactory, ActionExecutor


async def main():
    """Demonstrate reflexive core functionality."""
    print("🚀 Reflexive Core Example")
    print("=" * 50)
    
    # Create a FastMCP server with reflexive core
    server = FastMCP("ReflexiveExampleServer")
    
    # Enable the reflexive core
    reflexive_engine = server.enable_reflexive_core()
    
    # Add monitors
    policy_monitor = PolicyMonitor()
    ledger_monitor = LedgerMonitor()
    anomaly_detector = AnomalyDetector()
    
    reflexive_engine.add_monitor(policy_monitor)
    reflexive_engine.add_monitor(ledger_monitor)
    reflexive_engine.add_monitor(anomaly_detector)
    
    print(f"✅ Reflexive core enabled with {len(reflexive_engine.monitors)} monitors")
    
    # Start the reflexive engine
    await reflexive_engine.start()
    print("✅ Reflexive engine started")
    
    # Create action executor
    action_executor = ActionExecutor()
    
    # Example 1: Normal action (should be allowed)
    print("\n📋 Example 1: Normal Action")
    print("-" * 30)
    
    normal_action = ActionContext(
        action_id="normal_action_001",
        actor_id="authorized_user",
        action_type="data_read",
        resource_id="public_data",
        metadata={"authorized": True}
    )
    
    decision = await reflexive_engine._evaluate_action(normal_action)
    print(f"Decision: {decision.decision_type}")
    print(f"Risk Level: {decision.risk_level}")
    print(f"Reason: {decision.reason}")
    
    # Execute the action
    action = ActionFactory.create_action(decision)
    result = await action_executor.execute_action(action)
    print(f"Action Result: {action.get_action_type()} - {result.get('allowed', 'N/A')}")
    
    # Example 2: Policy violation (should be halted)
    print("\n🚨 Example 2: Policy Violation")
    print("-" * 30)
    
    violation_action = ActionContext(
        action_id="violation_action_002",
        actor_id="guest_user",
        action_type="admin_access",
        resource_id="admin_panel",
        metadata={"authorized": False}
    )
    
    decision = await reflexive_engine._evaluate_action(violation_action)
    print(f"Decision: {decision.decision_type}")
    print(f"Risk Level: {decision.risk_level}")
    print(f"Reason: {decision.reason}")
    
    # Execute the action
    action = ActionFactory.create_action(decision)
    result = await action_executor.execute_action(action)
    print(f"Action Result: {action.get_action_type()}")
    print(f"Halted Operations: {result.get('halted_operations', [])}")
    
    # Example 3: Anomaly detection (should be escalated)
    print("\n⚠️  Example 3: Anomaly Detection")
    print("-" * 30)
    
    # Simulate multiple rapid actions to trigger anomaly
    for i in range(25):
        rapid_action = ActionContext(
            action_id=f"rapid_action_{i:03d}",
            actor_id="suspicious_user",
            action_type="api_call",
            resource_id="api_endpoint"
        )
        anomaly_detector._update_patterns(rapid_action)
    
    # Now test the anomaly detection
    anomaly_action = ActionContext(
        action_id="anomaly_action_003",
        actor_id="suspicious_user",
        action_type="api_call",
        resource_id="api_endpoint"
    )
    
    decision = await reflexive_engine._evaluate_action(anomaly_action)
    print(f"Decision: {decision.decision_type}")
    print(f"Risk Level: {decision.risk_level}")
    print(f"Reason: {decision.reason}")
    
    # Execute the action
    action = ActionFactory.create_action(decision)
    result = await action_executor.execute_action(action)
    print(f"Action Result: {action.get_action_type()}")
    print(f"Escalation Target: {result.get('escalation_target', 'N/A')}")
    
    # Example 4: Risk simulation
    print("\n🎯 Example 4: Risk Simulation")
    print("-" * 30)
    
    risk_scenario = {
        "action_context": {
            "action_id": "simulation_action",
            "actor_id": "test_actor",
            "action_type": "privilege_escalation",
            "resource_id": "root_access",
            "metadata": {"escalation_attempt": True}
        },
        "monitors": [
            lambda ctx: {
                "type": "violation",
                "severity": "critical",
                "violations": [{
                    "rule": "privilege_escalation",
                    "message": "Unauthorized privilege escalation attempt",
                    "severity": "critical"
                }]
            }
        ]
    }
    
    decision = await reflexive_engine.simulate_risk(risk_scenario)
    print(f"Simulation Decision: {decision.decision_type}")
    print(f"Simulation Risk Level: {decision.risk_level}")
    print(f"Simulation Reason: {decision.reason}")
    
    # Example 5: Monitor statistics
    print("\n📊 Example 5: Monitor Statistics")
    print("-" * 30)
    
    policy_stats = policy_monitor.get_violation_stats()
    ledger_stats = ledger_monitor.get_integrity_stats()
    anomaly_stats = anomaly_detector.get_anomaly_stats()
    
    print(f"Policy Monitor - Total Violations: {policy_stats['total_violations']}")
    print(f"Policy Monitor - Actor Violations: {policy_stats['actor_violations']}")
    print(f"Ledger Monitor - Total Checks: {ledger_stats['total_checks']}")
    print(f"Anomaly Detector - Tracked Actors: {anomaly_stats['tracked_actors']}")
    
    # Example 6: Engine status
    print("\n🔧 Example 6: Engine Status")
    print("-" * 30)
    
    status = reflexive_engine.get_engine_status()
    print(f"Engine Running: {status['is_running']}")
    print(f"Monitor Count: {status['monitor_count']}")
    print(f"Queue Size: {status['queue_size']}")
    print(f"Decision Handlers: {status['decision_handlers']}")
    
    # Example 7: Action execution statistics
    print("\n📈 Example 7: Action Execution Statistics")
    print("-" * 30)
    
    exec_stats = action_executor.get_execution_stats()
    print(f"Total Actions: {exec_stats['total_actions']}")
    print(f"Completed Actions: {exec_stats['completed_actions']}")
    print(f"Failed Actions: {exec_stats['failed_actions']}")
    print(f"Success Rate: {exec_stats['success_rate']:.2%}")
    
    # Stop the reflexive engine
    await reflexive_engine.stop()
    print("\n✅ Reflexive engine stopped")
    
    print("\n🎉 Reflexive Core Example Complete!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
