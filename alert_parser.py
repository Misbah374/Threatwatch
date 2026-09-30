# Purpose:
# Parses raw Wazuh alerts and extracts the relevant security information.

import json


class AlertParser:
    def parse(self, raw_alert):
        alert_data = json.loads(raw_alert)

        return {
            "timestamp": alert_data.get("timestamp"),
            "rule_id": alert_data.get("rule", {}).get("id"),
            "description": alert_data.get("rule", {}).get("description"),
            "severity": alert_data.get("rule", {}).get("level"),
            "agent": alert_data.get("agent", {}).get("name"),
            "source_ip": alert_data.get("data", {}).get("srcip")
        }
