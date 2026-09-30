# Purpose:
# Reads raw security alerts from the Wazuh alert source.

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"


class AlertReader:
    def __init__(self, file_path=ALERT_FILE):
        self.file_path = file_path

    def read_alerts(self):
        with open(self.file_path, "r") as file:
            return file.readlines()
