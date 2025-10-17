"""
Risk scoring engine for security findings
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from ..models.findings import Finding, FindingType, RiskLevel
from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class RiskScoringEngine:
    """Advanced risk scoring engine for security findings"""
    
    # Base risk scores for different finding types (0-100 scale)
    BASE_RISK_SCORES = {
        FindingType.CRITICAL: 95.0,
        FindingType.MISCONFIGURATION: 60.0,
        FindingType.INACTIVE_USER: 40.0,
        FindingType.PUBLIC_SHARE: 80.0,
        FindingType.OVERPERMISSIVE_TOKEN: 75.0,
        FindingType.WEAK_PASSWORD_POLICY: 65.0,
        FindingType.MFA_DISABLED: 85.0,
        FindingType.EXCESSIVE_PERMISSIONS: 70.0,
        FindingType.EXTERNAL_SHARING: 75.0,
        FindingType.UNENCRYPTED_DATA: 90.0,
        FindingType.OUTDATED_SOFTWARE: 55.0
    }
    
    # Risk multipliers for different factors
    CONTEXT_MULTIPLIERS = {
        "admin_user": 1.5,           # Admin user involved
        "sensitive_data": 1.4,       # Contains sensitive data
        "external_access": 1.3,      # External access enabled
        "production_environment": 1.2, # Production system
        "recent_activity": 0.9,      # Recently active (lower risk for some findings)
        "compliance_scope": 1.3,     # In compliance scope (SOX, GDPR, etc.)
        "business_critical": 1.4,    # Business critical system
        "public_internet": 1.5,      # Exposed to public internet
        "shared_widely": 1.2,        # Shared with many users
        "no_monitoring": 1.3         # No security monitoring
    }
    
    def __init__(self):
        self.logger = logger.bind(component="risk_engine")
    
    def calculate_base_risk_score(self, finding_type: FindingType, evidence: Dict[str, Any]) -> float:
        """Calculate base risk score for finding type"""
        base_score = self.BASE_RISK_SCORES.get(finding_type, 50.0)
        
        # Apply evidence-specific adjustments
        if finding_type == FindingType.INACTIVE_USER:
            # Higher risk for admin users
            if evidence.get("is_admin", False):
                base_score *= 1.5
            
            # Lower risk if user was recently active
            last_login = evidence.get("last_login_days")
            if last_login and last_login < 30:
                base_score *= 0.8
            elif last_login and last_login > 180:
                base_score *= 1.2
        
        elif finding_type == FindingType.PUBLIC_SHARE:
            # Higher risk for sensitive file types
            sensitive_files = evidence.get("sensitive_files", 0)
            if sensitive_files > 0:
                base_score *= 1.3
            
            # Risk based on access count
            access_count = evidence.get("access_count", 0)
            if access_count > 100:
                base_score *= 1.2
        
        elif finding_type == FindingType.OVERPERMISSIVE_TOKEN:
            # Risk based on token scope
            scopes = evidence.get("scopes", [])
            high_risk_scopes = ["admin", "write", "delete", "full_access"]
            if any(scope in str(scopes).lower() for scope in high_risk_scopes):
                base_score *= 1.3
        
        return min(base_score, 100.0)  # Cap at 100
    
    def apply_context_multipliers(self, base_score: float, evidence: Dict[str, Any]) -> float:
        """Apply contextual risk multipliers"""
        final_score = base_score
        
        for context, multiplier in self.CONTEXT_MULTIPLIERS.items():
            if evidence.get(context, False):
                final_score *= multiplier
                self.logger.debug(
                    "Applied context multiplier",
                    context=context,
                    multiplier=multiplier,
                    score_before=base_score,
                    score_after=final_score
                )
        
        return min(final_score, 100.0)  # Cap at 100
    
    def calculate_temporal_factors(self, finding_data: Dict[str, Any]) -> float:
        """Calculate risk adjustments based on temporal factors"""
        multiplier = 1.0
        
        # Age of finding - older findings may be more entrenched
        first_seen = finding_data.get("first_seen_at")
        if first_seen:
            days_old = (datetime.utcnow() - first_seen).days
            if days_old > 30:
                multiplier *= 1.1  # Slightly higher risk for old findings
            if days_old > 90:
                multiplier *= 1.2  # Higher risk for very old findings
        
        # Frequency of occurrence
        occurrence_count = finding_data.get("occurrence_count", 1)
        if occurrence_count > 5:
            multiplier *= 1.1  # Recurring issues are riskier
        
        # Recent changes
        if finding_data.get("recent_changes", False):
            multiplier *= 1.15  # Recent changes increase risk
        
        return multiplier
    
    def determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level based on score"""
        if risk_score >= settings.CRITICAL_RISK_THRESHOLD:
            return RiskLevel.CRITICAL
        elif risk_score >= settings.HIGH_RISK_THRESHOLD:
            return RiskLevel.HIGH
        elif risk_score >= settings.MEDIUM_RISK_THRESHOLD:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def calculate_risk_score(
        self, 
        finding_type: FindingType, 
        evidence: Dict[str, Any],
        finding_data: Optional[Dict[str, Any]] = None
    ) -> tuple[float, RiskLevel]:
        """
        Calculate comprehensive risk score and level
        
        Args:
            finding_type: Type of security finding
            evidence: Evidence data specific to the finding
            finding_data: Additional finding metadata
            
        Returns:
            Tuple of (risk_score, risk_level)
        """
        finding_data = finding_data or {}
        
        # Step 1: Calculate base risk score
        base_score = self.calculate_base_risk_score(finding_type, evidence)
        
        # Step 2: Apply contextual multipliers
        contextual_score = self.apply_context_multipliers(base_score, evidence)
        
        # Step 3: Apply temporal factors
        temporal_multiplier = self.calculate_temporal_factors(finding_data)
        final_score = contextual_score * temporal_multiplier
        
        # Step 4: Cap at 100 and determine risk level
        final_score = min(final_score, 100.0)
        risk_level = self.determine_risk_level(final_score)
        
        self.logger.info(
            "Risk score calculated",
            finding_type=finding_type.value,
            base_score=base_score,
            contextual_score=contextual_score,
            temporal_multiplier=temporal_multiplier,
            final_score=final_score,
            risk_level=risk_level.value
        )
        
        return final_score, risk_level
    
    def calculate_organizational_risk_score(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate overall organizational risk score"""
        if not findings:
            return {
                "overall_score": 0.0,
                "risk_level": RiskLevel.LOW.value,
                "finding_counts": {},
                "top_risks": []
            }
        
        # Count findings by risk level
        risk_counts = {level.value: 0 for level in RiskLevel}
        total_weighted_score = 0.0
        
        # Weight factors for different risk levels
        risk_weights = {
            RiskLevel.CRITICAL: 4.0,
            RiskLevel.HIGH: 3.0,
            RiskLevel.MEDIUM: 2.0,
            RiskLevel.LOW: 1.0
        }
        
        for finding in findings:
            risk_counts[finding.risk_level.value] += 1
            total_weighted_score += finding.risk_score * risk_weights[finding.risk_level]
        
        # Calculate overall score (0-100)
        total_findings = len(findings)
        max_possible_score = total_findings * 100 * risk_weights[RiskLevel.CRITICAL]
        overall_score = (total_weighted_score / max_possible_score * 100) if max_possible_score > 0 else 0
        
        # Determine overall risk level
        overall_risk_level = self.determine_risk_level(overall_score)
        
        # Get top 5 highest risk findings
        top_risks = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:5]
        
        return {
            "overall_score": round(overall_score, 2),
            "risk_level": overall_risk_level.value,
            "finding_counts": risk_counts,
            "total_findings": total_findings,
            "top_risks": [
                {
                    "id": f.id,
                    "title": f.title,
                    "risk_score": f.risk_score,
                    "risk_level": f.risk_level.value,
                    "type": f.type.value
                }
                for f in top_risks
            ],
            "recommendations": self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Count finding types
        type_counts = {}
        for finding in findings:
            type_counts[finding.type] = type_counts.get(finding.type, 0) + 1
        
        # Generate recommendations based on most common issues
        if type_counts.get(FindingType.MFA_DISABLED, 0) > 0:
            recommendations.append("Enable multi-factor authentication for all user accounts")
        
        if type_counts.get(FindingType.PUBLIC_SHARE, 0) > 2:
            recommendations.append("Review and restrict public file sharing permissions")
        
        if type_counts.get(FindingType.INACTIVE_USER, 0) > 5:
            recommendations.append("Implement automated user deprovisioning for inactive accounts")
        
        if type_counts.get(FindingType.EXCESSIVE_PERMISSIONS, 0) > 0:
            recommendations.append("Conduct access review and implement least privilege principle")
        
        if type_counts.get(FindingType.WEAK_PASSWORD_POLICY, 0) > 0:
            recommendations.append("Strengthen password policy and enforce regular password changes")
        
        # Critical findings always get priority attention
        critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
        if critical_count > 0:
            recommendations.insert(0, f"Immediately address {critical_count} critical security findings")
        
        return recommendations[:5]  # Return top 5 recommendations


# Global risk scoring engine instance
risk_engine = RiskScoringEngine()
