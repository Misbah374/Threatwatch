import os
import secrets
from functools import wraps
from flask import request, jsonify

def verify_token():
    expected_key = os.getenv("THREATWATCH_API_KEY")
    if not expected_key:
        return False
    auth_header = request.headers.get("Authorization","")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    provided_key = parts[1]
    if not provided_key:
        return False
    return secrets.compare_digest(provided_key, expected_key)

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not verify_token():
            return jsonify({"error": "Unauthorized access"}), 401
        return func(*args, **kwargs)
    return wrapper
