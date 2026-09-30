# Purpose:
# Generates statistics and summaries from alerts and security incidents.

class StatisticsService:

    def generate(self, alerts, incidents):

        severity_counts = {}

        for alert in alerts:
            severity = alert.severity or 0

            if severity not in severity_counts:
                severity_counts[severity] = 0

            severity_counts[severity] += 1

        return {
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "severity_counts": severity_counts
        }
