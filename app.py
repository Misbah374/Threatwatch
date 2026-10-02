# Purpose:
# Creates and configures the Flask application and connects the API routes.

from flask import Flask

from routes import routes
from alert_reader import AlertReader
from alert_parser import AlertParser
from alert_normalizer import AlertNormalizer
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

    print("\n[3] Statistics...")
    stats = statistics.generate(alerts)

    print("\n    Overview:")
    overview = stats["overview"]

    print(f"      Total alerts       : {overview['total_alerts']}")
    print(f"      Unique rules       : {overview['unique_rules']}")
    print(f"      Unique agents      : {overview['unique_agents']}")
    print(f"      Unique source IPs  : {overview['unique_source_ips']}")

    print("\n    Severity distribution:")

    for severity, data in stats["severity"].items():
        label = "alert" if data["count"] == 1 else "alerts"

        print(
            f"      Level {severity:<2}: "
            f"{data['count']} {label} "
            f"({data['percentage']:.2f}%)"
        )

    print("\n    Top rules:")

    for rule in stats["rules"][:5]:
        print(
            f"      Rule {rule['rule_id']}: "
            f"{rule['count']} alerts"
        )
        print(
            f"        {rule['description']}"
        )

    print("\n    Source activity:")

    if stats["sources"]:
        for source in stats["sources"][:5]:
            print(
                f"      {source['source_ip']}: "
                f"{source['count']} alerts"
            )
    else:
        print("      No source IP information available.")

    print("\n    Agent activity:")

    if stats["agents"]:
        for agent in stats["agents"]:
            print(
                f"      {agent['agent']}: "
                f"{agent['count']} alerts"
            )
    else:
        print("      No agent information available.")

    print("\n    Time analysis:")

    time_stats = stats["time"]

    print(
        f"      First alert        : "
        f"{time_stats['first_alert']}"
    )

    print(
        f"      Last alert         : "
        f"{time_stats['last_alert']}"
    )

    print(
        f"      Observation period : "
        f"{time_stats['observation_duration']}"
    )

    print(
        f"      Busiest hour       : "
        f"{time_stats['busiest_hour']}"
    )

    print("\n[4] Last 5 alerts:")

    for alert in alerts[-5:]:
        print("\n    -------------------------")
        print(f"    Time       : "f"{statistics.format_timestamp(alert.timestamp)}")
        print(f"    Rule ID    : {alert.rule_id}")
        print(f"    Severity   : {alert.severity}")
        print(f"    Description: {alert.description}")
        print(f"    Agent      : {alert.agent}")
        print(f"    Source IP  : {alert.source_ip}")

    print("\n========== DEMO COMPLETE ==========\n")

if __name__ == "__main__":
    run_terminal_demo()
