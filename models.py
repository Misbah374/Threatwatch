# Purpose:
# Defines the core data models used by ThreatWatch, such as Alert and Incident

class Alert:
    def __init__(
        self,
        timestamp,
        rule_id,
        description,
        severity,
        agent,
        source_ip
    ):
        self.timestamp = timestamp
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.agent = agent
        self.source_ip = source_ip

class Incident:
    def __init__(
        self,
        incident_id,
        incident_type,
        severity,
        alerts
    ):
        self.incident_id = incident_id
        self.incident_type = incident_type
        self.severity = severity
        self.alerts = alerts
