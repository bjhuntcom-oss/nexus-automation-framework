"""
Nexus Automation Framework - Intelligence Module
================================================

Threat intelligence layer providing actionable CVE advisory, MITRE ATT&CK
technique mapping, and consolidated threat intelligence aggregation.

Exposed classes:
    CVEAdvisor       -- SQLite-backed CVE query engine with CVSS scoring and
                        exploit-chain analysis.
    MITREMapper      -- MITRE ATT&CK technique mapper with kill-chain
                        progression and detection-gap analysis.
    ThreatIntelligence -- High-level facade aggregating CVEAdvisor and
                          MITREMapper into a single cohesive API.

Typical usage::

    from nexus_framework.intelligence import CVEAdvisor, MITREMapper, ThreatIntelligence

    advisor = CVEAdvisor()
    cves = advisor.get_cves_for_service("apache", version="2.4.48")

    mapper = MITREMapper()
    techniques = mapper.map_finding_to_techniques("RCE via Log4Shell", "critical")

    ti = ThreatIntelligence()
    report = ti.full_assessment({"apache": "2.4.48", "openssh": "7.4"})
"""

from .cve_advisor import CVEAdvisor

__version__ = "1.0.0"
__author__ = "Nexus Development Team"

__all__ = [
    "CVEAdvisor",
]
