# Purpose:
# Analyzes normalized alerts, detects related patterns, and creates security incidents.

from models import Incident


class IncidentAnalyzer:

    def analyze(self, alerts):
        incidents = []

        groups = {}

        for alert in alerts:
            source_ip = alert.source_ip or "unknown"

            if source_ip not in groups:
                groups[source_ip] = []

            groups[source_ip].append(alert)

        incident_count = 1

        for source_ip, grouped_alerts in groups.items():

            if len(grouped_alerts) >= 2:

                highest_severity = max(
                    alert.severity or 0
                    for alert in grouped_alerts
                )

                incident = Incident(
                    incident_id=f"INC-{incident_count:03d}",
                    incident_type="Multiple alerts from same source",
                    severity=highest_severity,
                    alerts=grouped_alerts
                )

                incidents.append(incident)
                incident_count += 1

        return incidents
