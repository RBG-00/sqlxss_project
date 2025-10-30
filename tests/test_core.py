import subprocess, time, json, os, sys
import requests
import pytest

PY="python3"

@pytest.fixture(scope="module")
def test_server():
    p = subprocess.Popen([PY,"test_server.py"])
    time.sleep(1)
    yield
    p.terminate()
    p.wait()

def run_scanner(args):
    env = os.environ.copy()
    # ensure we run scanner in same dir
    res = subprocess.run([PY,"scanner.py"] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return res.returncode, res.stdout

def test_normalize_response_unit():
    from scanner import normalize_response
    s = "time: 2025-10-30T12:34:56Z id: a1b2c3d4"
    n = normalize_response(s)
    assert "2025-10-30T12:34:56Z" not in n
    assert "a1b2c3d4" not in n

def test_integration_auto_verify_sql(test_server):
    code, out = run_scanner(["-u","http://127.0.0.1:8080/vuln/sql?q=test","--auto-verify","--timeout","12","--len-threshold","0.2"])
    assert code == 0 or code == 0
    # parse report.json
    with open("report.json","r") as f:
        j=json.load(f)
    assert isinstance(j.get("findings"), list)
    assert any(f.get("auto_verified") for f in j.get("findings",[]))
