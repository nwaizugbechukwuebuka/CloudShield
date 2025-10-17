import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from src.api.services.risk_engine import RiskEngine, RiskContext
from src.api.models.findings import Finding, RiskLevel, FindingType

class TestRiskEngine:
    
    def test_risk_context_creation(self):
        """Test RiskContext initialization and default values."""
        context = RiskContext()
        
        assert context.user_count == 0
        assert context.admin_count == 0
        assert context.external_users == 0
        assert context.public_shares == 0
        assert context.compliance_requirements == []
        assert context.industry_sector is None
    
    def test_base_risk_scores(self):
        """Test base risk score calculation for different finding types."""
        engine = RiskEngine()
        
        # Test base scores for different finding types
        test_cases = [
            (FindingType.PUBLIC_SHARE, 80),
            (FindingType.OVERPRIVILEGED_TOKEN, 85),
            (FindingType.MISCONFIGURATION, 70),
            (FindingType.INACTIVE_USER, 50),
            (FindingType.SUSPICIOUS_ACTIVITY, 75),
            (FindingType.COMPLIANCE_VIOLATION, 80)
        ]
        
        for finding_type, expected_base in test_cases:
            score = engine._get_base_risk_score(finding_type)
            assert score == expected_base
    
    def test_temporal_multiplier(self):
        """Test temporal risk multiplier calculation."""
        engine = RiskEngine()
        
        # Recent finding should have higher multiplier
        recent_date = datetime.utcnow() - timedelta(hours=1)
        recent_multiplier = engine._calculate_temporal_multiplier(recent_date)
        assert recent_multiplier >= 1.0
        
        # Old finding should have lower multiplier
        old_date = datetime.utcnow() - timedelta(days=60)
        old_multiplier = engine._calculate_temporal_multiplier(old_date)
        assert old_multiplier < recent_multiplier
    
    def test_context_multiplier_high_risk_environment(self):
        """Test context multiplier in high-risk environment."""
        engine = RiskEngine()
        
        # High-risk context with many users and external access
        high_risk_context = RiskContext(
            user_count=1000,
            admin_count=50,
            external_users=200,
            public_shares=100,
            compliance_requirements=['SOX', 'GDPR'],
            industry_sector='financial'
        )
        
        multiplier = engine._calculate_context_multiplier(
            FindingType.PUBLIC_SHARE, 
            high_risk_context
        )
        
        # Should increase risk in high-risk environment
        assert multiplier > 1.0
    
    def test_context_multiplier_low_risk_environment(self):
        """Test context multiplier in low-risk environment."""
        engine = RiskEngine()
        
        # Low-risk context
        low_risk_context = RiskContext(
            user_count=5,
            admin_count=1,
            external_users=0,
            public_shares=0,
            compliance_requirements=[],
            industry_sector='technology'
        )
        
        multiplier = engine._calculate_context_multiplier(
            FindingType.INACTIVE_USER, 
            low_risk_context
        )
        
        # Should not significantly increase risk in low-risk environment
        assert multiplier <= 1.2
    
    def test_calculate_risk_score_integration(self):
        """Test complete risk score calculation."""
        engine = RiskEngine()
        
        # Create mock finding
        finding = Mock()
        finding.finding_type = FindingType.PUBLIC_SHARE
        finding.created_at = datetime.utcnow() - timedelta(hours=2)
        finding.metadata = {'file_count': 5}
        
        # Create context
        context = RiskContext(
            user_count=100,
            admin_count=10,
            external_users=20,
            public_shares=5,
            compliance_requirements=['GDPR'],
            industry_sector='healthcare'
        )
        
        # Calculate risk score
        score = engine.calculate_risk_score(finding, context)
        
        # Should be a valid score between 0 and 100
        assert 0 <= score <= 100
        assert isinstance(score, (int, float))
    
    def test_assess_finding_risk_level(self):
        """Test risk level assessment based on score."""
        engine = RiskEngine()
        
        test_cases = [
            (95, RiskLevel.CRITICAL),
            (85, RiskLevel.HIGH),
            (65, RiskLevel.MEDIUM),
            (25, RiskLevel.LOW)
        ]
        
        for score, expected_level in test_cases:
            level = engine.assess_finding_risk_level(score)
            assert level == expected_level
    
    def test_compliance_impact_calculation(self):
        """Test compliance impact on risk scoring."""
        engine = RiskEngine()
        
        # GDPR compliance context should increase data-related finding risks
        gdpr_context = RiskContext(
            compliance_requirements=['GDPR'],
            industry_sector='healthcare'
        )
        
        # Public share finding should have higher impact under GDPR
        public_share_multiplier = engine._calculate_context_multiplier(
            FindingType.PUBLIC_SHARE, 
            gdpr_context
        )
        
        # Should increase risk due to GDPR data protection requirements
        assert public_share_multiplier > 1.0
    
    def test_industry_specific_risk_assessment(self):
        """Test industry-specific risk assessment."""
        engine = RiskEngine()
        
        # Financial sector should have higher security requirements
        financial_context = RiskContext(
            industry_sector='financial',
            compliance_requirements=['SOX', 'PCI_DSS']
        )
        
        # Security misconfigurations should be higher risk in financial sector
        multiplier = engine._calculate_context_multiplier(
            FindingType.MISCONFIGURATION, 
            financial_context
        )
        
        assert multiplier >= 1.0
    
    def test_metadata_impact_on_scoring(self):
        """Test how finding metadata impacts risk scoring."""
        engine = RiskEngine()
        
        # Finding with high impact metadata
        high_impact_finding = Mock()
        high_impact_finding.finding_type = FindingType.PUBLIC_SHARE
        high_impact_finding.created_at = datetime.utcnow()
        high_impact_finding.metadata = {
            'file_count': 100,
            'sensitive_files': 50,
            'external_shares': 25
        }
        
        # Finding with low impact metadata
        low_impact_finding = Mock()
        low_impact_finding.finding_type = FindingType.PUBLIC_SHARE
        low_impact_finding.created_at = datetime.utcnow()
        low_impact_finding.metadata = {
            'file_count': 1,
            'sensitive_files': 0,
            'external_shares': 0
        }
        
        context = RiskContext()
        
        high_score = engine.calculate_risk_score(high_impact_finding, context)
        low_score = engine.calculate_risk_score(low_impact_finding, context)
        
        # High impact finding should have higher score
        assert high_score > low_score

if __name__ == "__main__":
    pytest.main([__file__, "-v"])