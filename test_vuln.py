# test_vuln.py
from flask import Flask, request
app = Flask(__name__)

@app.route("/vuln", methods=["GET","POST"])
def vuln():
    if request.method == "GET":
        q = request.args.get("q","")
        return f"<html><body>Search result: {q}</body></html>"
    else:
        data = request.get_json(silent=True) or {}
        q = data.get("q","")
        return f"<html><body>POST result: {q}</body></html>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)
