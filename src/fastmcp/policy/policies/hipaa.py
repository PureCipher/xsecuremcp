"""
Actor-Aware HIPAA Policy Implementation
"""

from typing import Any, Dict, List
from datetime import datetime, timedelta

from ..policy import Policy
from ..decision import Decision


class HIPAAAccessPolicy(Policy):
    """
    Policy that implements an actor-aware set of HIPAA security and privacy rules.
    """

    def __init__(self, name: str = "hipaa", version: str = "1.0.0"):
        super().__init__(name, version)
        self.permitted_purposes = [
            "treatment", 
            "payment", 
            "operations", 
            "public_health", 
            "health_oversight",
            "law_enforcement", 
            "research", 
            "threat_to_health_or_safety", 
            "self_access"
        ]

    async def evaluate(self, context: Dict[str, Any]) -> Decision:
        """
        Evaluate the context against HIPAA regulations.

        Args:
            context: The context containing user, action, resource, and purpose information.

        Returns:
            Decision indicating whether access is allowed or denied.
        """
        resource = context.get("resource", {})

        # 1. Pre-Evaluation: Check if the resource is PHI
        if not resource.get("is_phi", False):
            return Decision.allow_decision("Policy does not apply to non-PHI resources.")

        # Handle emergency access
        if context.get("is_emergency_access", False):
            return self._evaluate_emergency_access(context)

        # 2. Patient Rights Evaluation
        patient_decision = self._evaluate_patient_rights(context)
        if patient_decision:
            return patient_decision

        # 3. Authorization and Consent Evaluation
        auth_decision = self._evaluate_authorizations(context)
        if auth_decision:
            return auth_decision

        # 4. Actor-Specific Rule Evaluation (New)
        actor_decision = self._evaluate_actor_specific_rules(context)
        if not actor_decision.allow:
            return actor_decision

        # If all checks pass, return the decision from the actor-specific evaluation
        return actor_decision

    def _evaluate_patient_rights(self, context: Dict[str, Any]) -> Decision | None:
        """Check for patient-asserted rights like restrictions and deceased status."""
        patient = context.get("patient", {})
        if patient.get("has_restriction", False):
            restriction = patient.get("restriction_details", {})
            if (restriction.get("action") == context.get("action") and
                restriction.get("recipient") == context.get("recipient", {}).get("id")):
                return Decision.deny_decision(
                    reason="Disclosure is blocked by a patient-requested restriction.",
                    proof={"policy": self.name, "citation": "§ 164.522(a)(1)"}
                )

        if patient.get("is_deceased", False):
            date_of_death_str = patient.get("date_of_death")
            if date_of_death_str:
                date_of_death = datetime.strptime(date_of_death_str, "%Y-%m-%d")
                if datetime.now() > date_of_death + timedelta(days=365.25 * 50):
                    return Decision.allow_decision(
                        reason="Patient deceased for over 50 years; information is not considered PHI.",
                        proof={"policy": self.name, "citation": "§ 164.502(f)"}
                    )
        return None

    def _evaluate_authorizations(self, context: Dict[str, Any]) -> Decision | None:
        """Check for uses that require explicit authorization."""
        resource = context.get("resource", {})
        request = context.get("request", {})
        purpose = context.get("purpose", "").lower()

        if resource.get("type") == "psychotherapy_notes" and purpose != "treatment":
            if not request.get("authorization_present", False):
                return Decision.deny_decision(
                    reason="Disclosure of psychotherapy notes requires specific patient authorization.",
                    proof={"policy": self.name, "citation": "§ 164.508(a)(2)"}
                )

        if purpose in ["marketing", "sale_of_phi"]:
            if not request.get("authorization_present", False):
                return Decision.deny_decision(
                    reason=f"Purpose '{purpose}' requires patient authorization.",
                    proof={"policy": self.name, "citation": "§ 164.508(a)(3-4)"}
                )
        return None

    def _evaluate_actor_specific_rules(self, context: Dict[str, Any]) -> Decision:
        """Route to the correct logic based on the user's role (actor)."""
        user_roles = context.get("user", {}).get("roles", [])

        if "provider" in user_roles:
            return self._evaluate_provider_access(context)
        if "payee" in user_roles:
            return self._evaluate_payee_access(context)
        if "patient" in user_roles:
            return self._evaluate_patient_self_access(context)

        return Decision.deny_decision(
            "User does not have a recognized HIPAA actor role (provider, payee, patient)."
        )

    def _evaluate_provider_access(self, context: Dict[str, Any]) -> Decision:
        """Evaluate access for a clinical provider."""
        # Minimum necessary check
        min_necessary_decision = self._check_minimum_necessary(context)
        if not min_necessary_decision.allow:
            return min_necessary_decision

        obligations = [
            {
                "type": "audit_log", 
                "description": f"Provider {context['user']['id']} accessed PHI for {context['purpose']}."
            }
        ]
        if context['action'] == 'disclose':
            obligations.append(
                {
                    "type": "transmission_security", 
                    "description": "PHI disclosure must be encrypted."
                }
            )

        return Decision.allow_decision(
            reason="Provider access permitted for a valid purpose.",
            obligations=obligations,
            proof={
                "policy": self.name, 
                "actor": "provider", 
                "citations": ["164.502(b)", "164.308(a)(1)(ii)(D)", "164.312(e)(1)"]
            }
        )

    def _evaluate_payee_access(self, context: Dict[str, Any]) -> Decision:
        """Evaluate access for a payee (billing staff)."""
        # Data Integrity Check: Payees cannot modify clinical data.
        resource = context.get("resource", {})
        action = context.get("action")
        if resource.get("is_clinical", False) and action in ["write", "delete"]:
            return Decision.deny_decision(
                reason="Payee role is prohibited from modifying clinical PHI to ensure data integrity.",
                proof={"policy": self.name, "actor": "payee", "citation": "164.312(c)(1)"}
            )

        min_necessary_decision = self._check_minimum_necessary(context)
        if not min_necessary_decision.allow:
            return min_necessary_decision

        obligations = [
            {
                "type": "audit_log", 
                "description": f"Payee {context['user']['id']} accessed PHI for {context['purpose']}."
            }
        ]
        if action == 'export':
            obligations.append(
                {"type": "encryption", "description": "Exported PHI must be encrypted."}
            )

        return Decision.allow_decision(
            reason="Payee access to non-clinical data permitted.",
            obligations=obligations,
            proof={
                "policy": self.name, 
                "actor": "payee", 
                "citations": ["164.502(b)", "164.312(a)(2)(iv)"]
            }
        )

    def _evaluate_patient_self_access(self, context: Dict[str, Any]) -> Decision:
        """Evaluate a patient's access to their own records."""
        user = context.get("user", {})
        patient = context.get("patient", {})

        if user.get("id") != patient.get("id"):
            return Decision.deny_decision("Patient role can only access their own records.")

        # Minimum necessary does not apply to patient's own request
        obligations = [
             {"type": "audit_log", "description": f"Patient {user['id']} accessed their own PHI."}
        ]
        if context['action'] == 'export':
            obligations.append(
                {
                    "type": "encryption", 
                    "description": "Exported PHI must be provided securely/encrypted."
                }
            )

        return Decision.allow_decision(
            reason="Patient has a right of access to their own PHI; minimum necessary does not apply.",
            obligations=obligations,
            proof={
                "policy": self.name, 
                "actor": "patient", 
                "citations": ["164.524", "164.312(a)(2)(iv)"]
            }
        )

    def _check_minimum_necessary(self, context: Dict[str, Any]) -> Decision:
        """Enforce the Minimum Necessary principle based on role and purpose."""
        user = context.get("user", {})
        resource = context.get("resource", {})
        purpose = context.get("purpose", "").lower()
        requested_elements = resource.get("data_elements", [])

        if purpose == "treatment":
            return Decision.allow_decision(
                "Minimum Necessary does not apply to disclosures for treatment."
            )

        role_permissions = {
            "provider": ["full_record"],
            "payee": ["demographics", "billing_codes", "dates_of_service", "insurance_info"],
            "admin": ["full_record"]
        }
        user_roles = user.get("roles", [])
        permitted_elements = set()
        for role in user_roles:
            if role in role_permissions:
                if "full_record" in role_permissions[role]:
                    return Decision.allow_decision("User role permits access to the full record.")
                permitted_elements.update(role_permissions[role])

        if not set(requested_elements).issubset(permitted_elements):
            return Decision.deny_decision(
                reason="Request exceeds the minimum necessary information for the user's role.",
                proof={
                    "policy": self.name, "citation": "§ 164.502(b)",
                    "user_roles": user_roles,
                    "permitted_elements": list(permitted_elements),
                    "requested_elements": requested_elements
                }
            )
        return Decision.allow_decision("Minimum Necessary check passed.")

    def _evaluate_emergency_access(self, context: Dict[str, Any]) -> Decision:
        """Evaluate access during a declared emergency situation."""
        return Decision.allow_decision(
            reason="Access permitted under emergency provisions.",
            obligations=[
                {
                    "type": "audit_log", 
                    "description": f"EMERGENCY access to PHI by {context['user']['id']} was permitted."
                },
                {
                    "type": "follow_up", 
                    "description": "Document the nature of the emergency and what was disclosed."
                }
            ],
            proof={"policy": self.name, "citation": "§ 164.510 / § 164.512(j)"}
        )