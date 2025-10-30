# save as test_server.py
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return "OK - simple home"

@app.route("/echo", methods=["GET","POST"])
def echo():
    # support query param or form or json
    payload = None
    if request.method == "GET":
        payload = request.args.get("q","")
    else:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            payload = j.get("q","")
        else:
            payload = request.form.get("q","")

    # simulate SQL error pattern if contains "'"
    if "'" in (payload or ""):
        return "you have an error in your sql syntax near ...", 200

    # simulate time-based delay for payload containing SLEEP
    if "SLEEP" in (payload or "").upper() or "WAITFOR" in (payload or "").upper():
        time.sleep(2)
        return jsonify({"result": "delayed", "payload": payload})

    # reflect payload for XSS check
    if payload:
        return f"Echo: {payload}"

    return "no payload"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
