# Purpose:
# Converts parsed alert data into a consistent ThreatWatch alert format.

from models import Alert


class AlertNormalizer:

    def normalize(self, parsed_alert):
        return Alert(
            timestamp=parsed_alert.get("timestamp"),
            rule_id=parsed_alert.get("rule_id"),
            description=parsed_alert.get("description"),
            severity=parsed_alert.get("severity"),
            agent=parsed_alert.get("agent"),
            source_ip=parsed_alert.get("source_ip")
        )
