from flask import Flask, request, redirect, render_template_string
import time

app = Flask(__name__)

DB = []  # تخزين بسيط بالذاكرة

FORM_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Stored XSS Lab</title></head>
<body>
  <h2>Submit Comment</h2>
  <form method="POST" action="/submit">
    <input name="comment" placeholder="write something..." style="width:420px" />
    <button type="submit">Send</button>
  </form>

  <p><a href="/view">Go to View Page</a></p>
</body>
</html>
"""

# 🔴 صفحة العرض: intentionally vulnerable (يعرض بدون escaping)
VIEW_HTML_VULN = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>View</title></head>
<body>
  <h2>View Comments (VULNERABLE)</h2>
  <div>
    {% for c in items %}
      <div style="border:1px solid #ddd;padding:8px;margin:6px 0;">
        {{ c | safe }}
      </div>
    {% endfor %}
  </div>
  <p><a href="/">Back</a></p>
</body>
</html>
"""

@app.get("/")
def index():
    return FORM_HTML

@app.post("/submit")
def submit():
    c = request.form.get("comment", "")
    # simulate storage delay
    DB.append(f"{time.time()}: {c}")
    return redirect("/view")

@app.get("/view")
def view():
    return render_template_string(VIEW_HTML_VULN, items=DB)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
