# Purpose:
# Defines Flask API routes that expose ThreatWatch functionality to clients.

from flask import Blueprint, jsonify

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
