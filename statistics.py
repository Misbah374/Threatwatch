# Purpose:
# Generates statistics

from collections import Counter
from datetime import datetime, timezone, timedelta

class StatisticsService:

    IST = timezone(timedelta(hours=5, minutes=30))

    def format_timestamp(self, timestamp):
        if not timestamp:
            return None

        try:
            timestamp = datetime.strptime(
                timestamp,
                "%Y-%m-%dT%H:%M:%S.%f%z"
            )

            timestamp = timestamp.astimezone(self.IST)

            return timestamp.strftime(
                "%d %b %Y, %I:%M:%S %p IST"
            )

        except ValueError:
            return timestamp

    def generate(self, alerts):
        return {
            "overview": self._overview(alerts),
            "severity": self._severity(alerts),
            "rules": self._rules(alerts),
            "sources": self._sources(alerts),
            "agents": self._agents(alerts),
            "time": self._time_statistics(alerts)
        }

    def _overview(self, alerts):
        rules = {
            alert.rule_id
            for alert in alerts
            if alert.rule_id is not None
        }

        agents = {
            alert.agent
            for alert in alerts
            if alert.agent
        }

        source_ips = {
            alert.source_ip
            for alert in alerts
            if alert.source_ip
        }

        return {
            "total_alerts": len(alerts),
            "unique_rules": len(rules),
            "unique_agents": len(agents),
            "unique_source_ips": len(source_ips)
        }

    def _severity(self, alerts):
        counts = Counter(
            alert.severity or 0
            for alert in alerts
        )

        total = len(alerts)

        distribution = {}

        for severity, count in sorted(counts.items()):
            percentage = (count / total * 100) if total else 0

            distribution[severity] = {
                "count": count,
                "percentage": round(percentage, 2)
            }

        return distribution

    def _rules(self, alerts):
        rule_counts = Counter(
            alert.rule_id
            for alert in alerts
            if alert.rule_id is not None
        )

        rule_descriptions = {}

        for alert in alerts:
            if alert.rule_id is not None:
                rule_descriptions[alert.rule_id] = alert.description

        rules = []

        for rule_id, count in rule_counts.most_common():
            rules.append({
                "rule_id": rule_id,
                "description": rule_descriptions.get(rule_id),
                "count": count
            })

        return rules

    def _sources(self, alerts):
        source_counts = Counter(
            alert.source_ip
            for alert in alerts
            if alert.source_ip
        )

        return [
            {
                "source_ip": source_ip,
                "count": count
            }
            for source_ip, count in source_counts.most_common()
        ]

    def _agents(self, alerts):
        agent_counts = Counter(
            alert.agent
            for alert in alerts
            if alert.agent
        )

        return [
            {
                "agent": agent,
                "count": count
            }
            for agent, count in agent_counts.most_common()
        ]

    def _time_statistics(self, alerts):
        timestamps = []

        for alert in alerts:
            if not alert.timestamp:
                continue

            try:
                timestamp = datetime.strptime(
                    alert.timestamp,
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )

                timestamps.append(
                    timestamp.astimezone(self.IST)
                )

            except ValueError:
                continue

        if not timestamps:
            return {
                "first_alert": None,
                "last_alert": None,
                "observation_duration_seconds": 0,
                "busiest_hour": None
            }

        first_alert = min(timestamps)
        last_alert = max(timestamps)

        duration = last_alert - first_alert

        total_seconds = int(duration.total_seconds())

        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        duration_parts = []

        if hours:
            duration_parts.append(f"{hours}h")

        if minutes:
            duration_parts.append(f"{minutes}m")

        if seconds or not duration_parts:
            duration_parts.append(f"{seconds}s")

        observation_duration = " ".join(duration_parts)

        hour_counts = Counter(
            timestamp.hour
            for timestamp in timestamps
        )

        busiest_hour = hour_counts.most_common(1)[0][0]

        return {
            "first_alert": first_alert.strftime(
                "%d %b %Y, %I:%M:%S %p IST"
            ),
            "last_alert": last_alert.strftime(
                "%d %b %Y, %I:%M:%S %p IST"
            ),
            "observation_duration": observation_duration,
            "busiest_hour":(
                f"{busiest_hour:02d}:00"
                f" - {(busiest_hour + 1)%24:02d}:00 IST"
            )
        }
