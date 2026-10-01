# Purpose:
# Defines Flask API routes that expose ThreatWatch functionality to clients.

from flask import Blueprint, jsonify
from statistics import StatisticsService
from alert_reader import AlertReader
from alert_parser import AlertParser
from alert_normalizer import AlertNormalizer
from incident_analyzer import IncidentAnalyzer


routes = Blueprint("routes", __name__)


@routes.route("/")
def home():
    return jsonify({
        "project": "ThreatWatch",
        "status": "running"
    })


@routes.route("/health")
def health():
    return jsonify({
        "status": "healthy"
    })


@routes.route("/incidents")
def incidents():

    reader = AlertReader()
    parser = AlertParser()
    normalizer = AlertNormalizer()
    analyzer = IncidentAnalyzer()

    raw_alerts = reader.read_alerts()

    alerts = []

    for raw_alert in raw_alerts:
        try:
            parsed_alert = parser.parse(raw_alert)
            alert = normalizer.normalize(parsed_alert)
            alerts.append(alert)
        except Exception:
            continue

    detected_incidents = analyzer.analyze(alerts)

    result = []

    for incident in detected_incidents:
        result.append({
            "incident_id": incident.incident_id,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "alert_count": len(incident.alerts)
        })

    return jsonify({
        "total_incidents": len(result),
        "incidents": result
    })

@routes.route("/statistics")
def statistics():

    reader = AlertReader()
    parser = AlertParser()
    normalizer = AlertNormalizer()
    analyzer = IncidentAnalyzer()
    statistics_service = StatisticsService()

    raw_alerts = reader.read_alerts()

    alerts = []

    for raw_alert in raw_alerts:
        try:
            parsed_alert = parser.parse(raw_alert)
            alert = normalizer.normalize(parsed_alert)
            alerts.append(alert)
        except Exception:
            continue

    incidents = analyzer.analyze(alerts)

    stats = statistics_service.generate(alerts, incidents)

    return jsonify(stats)

@routes.route("/alerts")
def alerts():

    reader = AlertReader()
    parser = AlertParser()
    normalizer = AlertNormalizer()

    raw_alerts = reader.read_alerts()

    alerts = []

    for raw_alert in raw_alerts:
        try:
            parsed_alert = parser.parse(raw_alert)
            alert = normalizer.normalize(parsed_alert)
            alerts.append(alert)
        except Exception:
            continue

    result = []

    for alert in alerts:
        result.append({
            "timestamp": alert.timestamp,
            "rule_id": alert.rule_id,
            "description": alert.description,
            "severity": alert.severity,
            "agent": alert.agent,
            "source_ip": alert.source_ip
        })

    return jsonify({
        "total_alerts": len(result),
        "alerts": result
    })
