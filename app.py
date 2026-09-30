# Purpose:
# Creates and configures the Flask application and connects the API routes.

from flask import Flask

from routes import routes
from alert_reader import AlertReader
from alert_parser import AlertParser
from alert_normalizer import AlertNormalizer
from incident_analyzer import IncidentAnalyzer
from statistics import StatisticsService


def create_app():
    app = Flask(__name__)
    app.register_blueprint(routes)

    return app


def run_terminal_demo():

    print("\n========== THREATWATCH ==========\n")

    reader = AlertReader()
    parser = AlertParser()
    normalizer = AlertNormalizer()
    analyzer = IncidentAnalyzer()
    statistics = StatisticsService()

    print("[1] Reading Wazuh alerts...")

    raw_alerts = reader.read_alerts()

    print(f"    Raw alerts found: {len(raw_alerts)}")

    alerts = []

    print("\n[2] Parsing and normalizing alerts...")

    for raw_alert in raw_alerts:

        try:
            parsed_alert = parser.parse(raw_alert)
            alert = normalizer.normalize(parsed_alert)

            alerts.append(alert)

        except Exception:
            continue

    print(f"    Valid alerts processed: {len(alerts)}")

    print("\n[3] Detecting incidents...")

    incidents = analyzer.analyze(alerts)

    print(f"    Incidents detected: {len(incidents)}")

    print("\n[4] Statistics...")

    stats = statistics.generate(alerts, incidents)

    print(f"    Total alerts     : {stats['total_alerts']}")
    print(f"    Total incidents  : {stats['total_incidents']}")

    print("\n    Severity counts:")

    for severity, count in stats["severity_counts"].items():
        print(f"      Level {severity}: {count}")

    print("\n[5] Last 30 alerts:")

    for alert in alerts[-30:]:
        print("\n    -------------------------")
        print(f"    Time       : {alert.timestamp}")
        print(f"    Rule ID    : {alert.rule_id}")
        print(f"    Severity   : {alert.severity}")
        print(f"    Description: {alert.description}")
        print(f"    Agent      : {alert.agent}")
        print(f"    Source IP  : {alert.source_ip}")

    print("\n[6] Detected incidents:")

    for incident in incidents:

        print("\n    =========================")
        print(f"    ID       : {incident.incident_id}")
        print(f"    Type     : {incident.incident_type}")
        print(f"    Severity : {incident.severity}")
        print(f"    Alerts   : {len(incident.alerts)}")

    print("\n========== DEMO COMPLETE ==========\n")


if __name__ == "__main__":
    run_terminal_demo()
