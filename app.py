from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
from datetime import datetime
import subprocess
import xml.etree.ElementTree as ET
import json
import uuid
import re

from pdf_report import build_pdf_report

app = Flask(__name__)

NMAP_BIN = "nmap"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
HISTORY_FILE = Path("scan_history.json")

SEVERITIES = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

SCAN_PROFILES = {
    "host_discovery": {
        "label": "Host Discovery",
        "description": "Discover live hosts without a port scan.",
        "mode": "host",
    },
    "quick": {
        "label": "Quick Scan",
        "description": "Fast scan of the top 100 TCP ports.",
        "mode": "tcp",
        "top_ports": 100,
    },
    "standard": {
        "label": "Standard Scan",
        "description": "Top 1000 TCP ports with service/version detection.",
        "mode": "tcp",
        "top_ports": 1000,
    },
    "full": {
        "label": "Full TCP Scan",
        "description": "Scan all TCP ports.",
        "mode": "tcp",
        "all_ports": True,
    },
    "udp": {
        "label": "UDP Scan",
        "description": "Scan common UDP ports and identify services.",
        "mode": "udp",
        "top_ports": 50,
    },
    "comprehensive": {
        "label": "Comprehensive Scan",
        "description": "TCP scan with service detection, OS detection and NSE.",
        "mode": "tcp",
        "top_ports": 1000,
    },
    "targeted": {
        "label": "Targeted Scan",
        "description": "Scan only the ports you specify.",
        "mode": "tcp",
        "targeted": True,
    },
}

NSE_OPTIONS = {
    "none": {"label": "No NSE Scripts", "selector": None},
    "safe": {"label": "Safe Scripts", "selector": "safe"},
    "default": {"label": "Default Scripts", "selector": "default"},
    "discovery": {"label": "Discovery Scripts", "selector": "discovery"},
    "web": {"label": "Web + TLS", "selector": "http-title,ssl-cert"},
    "vuln": {"label": "Vulnerability Scripts", "selector": "vuln"},
}

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)")

def load_history():
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []

def save_history(item):
    h = load_history()
    h.insert(0, item)
    HISTORY_FILE.write_text(json.dumps(h[:25], indent=2))

def validate_target(target):
    if not target or len(target) > 255:
        return False, "Enter a valid target."
    if any(x in target for x in [";", "|", "&", "`", "$", "\n", "\r"]):
        return False, "Invalid target characters."
    return True, ""

def validate_ports(value):
    if not value or not re.fullmatch(r"[0-9,\-\s]+", value):
        return False, "Use ports such as 22,80,443 or 1-1000."
    try:
        for part in value.replace(" ", "").split(","):
            if "-" in part:
                a, b = map(int, part.split("-", 1))
                if not (1 <= a <= b <= 65535):
                    return False, "Port ranges must be between 1 and 65535."
            else:
                if not 1 <= int(part) <= 65535:
                    return False, "Ports must be between 1 and 65535."
    except Exception:
        return False, "Invalid port list."
    return True, ""

def severity(score):
    if score >= 9: return "critical"
    if score >= 7: return "high"
    if score >= 4: return "medium"
    if score > 0: return "low"
    return "info"

def run_nmap(target, args, xml_path, timeout=900):
    command = [NMAP_BIN] + args + ["-oX", str(xml_path), target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 and not xml_path.exists():
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Nmap failed.")
    return " ".join(command)

def parse_script(script_id, port, protocol, output, counts):
    cves = []
    for cve, score_text in CVE_RE.findall(output or ""):
        try:
            score = float(score_text)
        except ValueError:
            continue
        sev = severity(score)
        counts[sev] += 1
        cves.append({"cve": cve, "score": score, "severity": sev})
    return {
        "script": script_id,
        "port": port,
        "protocol": protocol,
        "severity": max([x["severity"] for x in cves], key=lambda x: ["info","low","medium","high","critical"].index(x)) if cves else "info",
        "output": output,
        "cves": cves,
    }

def parse_xml(xml_path):
    root = ET.parse(xml_path).getroot()
    counts = dict(SEVERITIES)
    hosts = []

    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"

        addresses = []
        for a in host.findall("address"):
            addresses.append({
                "address": a.get("addr", ""),
                "type": a.get("addrtype", ""),
                "vendor": a.get("vendor", "")
            })

        address = next((a["address"] for a in addresses if a["type"] in ("ipv4","ipv6")),
                       addresses[0]["address"] if addresses else "unknown")

        hostnames = []
        hn = host.find("hostnames")
        if hn is not None:
            hostnames = [x.get("name","") for x in hn.findall("hostname")]

        os_name = "Not detected"
        os_accuracy = None
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name", "Unknown")
                os_accuracy = match.get("accuracy")

        ports = []
        scripts = []
        findings = []

        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state","unknown") if state_el is not None else "unknown"
                service_el = p.find("service")
                service = {
                    "name": service_el.get("name","") if service_el is not None else "",
                    "product": service_el.get("product","") if service_el is not None else "",
                    "version": service_el.get("version","") if service_el is not None else "",
                    "extra": service_el.get("extrainfo","") if service_el is not None else "",
                }

                if state == "open":
                    ports.append({
                        "port": p.get("portid",""),
                        "protocol": p.get("protocol",""),
                        "state": state,
                        "service": service
                    })

                for s in p.findall("script"):
                    output = s.get("output","").strip()
                    if not output:
                        continue
                    item = parse_script(s.get("id",""), p.get("portid",""), p.get("protocol",""), output, counts)
                    scripts.append(item)
                    if item["cves"] or item["script"] in ("vulners","vuln"):
                        findings.append(item)

        hosts.append({
            "address": address,
            "status": status,
            "addresses": addresses,
            "hostnames": hostnames,
            "os": os_name,
            "os_confidence": os_accuracy,
            "ports": ports,
            "scripts": scripts,
            "findings": findings
        })

    return {
        "hosts": hosts,
        "severity_counts": counts,
        "nmap_version": root.get("version",""),
        "nmap_args": root.get("args","")
    }

def make_args(profile, top_ports, custom_ports, nse, os_detect):
    if profile["mode"] == "host":
        return ["-sn", "-n"], 600

    args = ["-T4", "-Pn", "-n"]

    if profile["mode"] == "udp":
        args += ["-sU"]
    else:
        args += ["-sS"]

    if profile["label"] != "Quick Scan":
        args += ["-sV"]

    if os_detect and profile["mode"] == "tcp":
        args += ["-O"]

    if nse != "none":
        selector = NSE_OPTIONS[nse]["selector"]
        args += ["--script", selector, "--script-timeout", "30s"]

    if profile.get("targeted"):
        args += ["-p", custom_ports]
    elif profile.get("all_ports"):
        args += ["-p-"]
    else:
        args += ["--top-ports", str(top_ports)]

    return args, 1200 if profile["mode"] == "udp" else 900

def risk_score(result):
    c = result["summary"]["findings_by_severity"]
    score = c["critical"]*25 + c["high"]*15 + c["medium"]*8 + c["low"]*3
    score += min(result["summary"]["open_ports"] * 2, 20)
    score = min(score, 100)
    label = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return {"score": score, "label": label}

def summarize(result):
    hosts = result["hosts"]
    result["summary"] = {
        "hosts_up": sum(1 for h in hosts if h["status"] == "up"),
        "hosts_scanned": len(hosts),
        "open_ports": sum(len(h["ports"]) for h in hosts),
        "scripts_run": sum(len(h["scripts"]) for h in hosts),
        "findings_total": sum(len(h["findings"]) for h in hosts),
        "findings_by_severity": result.pop("_severity_counts", dict(SEVERITIES))
    }
    result["summary"]["risk"] = risk_score(result)
    return result

def compare(current, previous):
    if not previous:
        return {"available": False, "message": "No previous scan available."}

    def ports(scan):
        return {f'{h["address"]}:{p["port"]}/{p["protocol"]}' for h in scan.get("hosts",[]) for p in h.get("ports",[])}
    now, old = ports(current), ports(previous)
    return {
        "available": True,
        "new_ports": sorted(now-old),
        "closed_ports": sorted(old-now),
        "previous_risk": previous.get("summary",{}).get("risk",{}),
        "current_risk": current.get("summary",{}).get("risk",{})
    }

@app.route("/")
def index():
    return render_template("index.html", scan_profiles=SCAN_PROFILES, nse_options=NSE_OPTIONS)

@app.route("/scan-profiles")
def profiles():
    return jsonify({k: {"label":v["label"],"description":v["description"]} for k,v in SCAN_PROFILES.items()})

@app.route("/nse-options")
def nse():
    return jsonify(NSE_OPTIONS)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target","")).strip()
    scan_type = str(data.get("scan_type","standard"))
    top_ports = int(data.get("top_ports",1000))
    custom_ports = str(data.get("ports","")).strip()
    nse_choice = str(data.get("nse","safe"))
    os_detect = bool(data.get("os_detect",False))

    ok, message = validate_target(target)
    if not ok:
        return jsonify({"status":"error","message":message}),400
    if scan_type not in SCAN_PROFILES:
        return jsonify({"status":"error","message":"Unknown scan profile."}),400
    if nse_choice not in NSE_OPTIONS:
        return jsonify({"status":"error","message":"Unknown NSE selection."}),400

    profile = SCAN_PROFILES[scan_type]
    if profile.get("targeted"):
        ok, message = validate_ports(custom_ports)
        if not ok:
            return jsonify({"status":"error","message":message}),400

    run_id = uuid.uuid4().hex
    xml = Path(f"scan_{run_id}.xml")

    try:
        args, timeout = make_args(profile, top_ports, custom_ports, nse_choice, os_detect)
        command = run_nmap(target,args,xml,timeout)
        parsed = parse_xml(xml)

        result = {
            "status":"success",
            "id":run_id,
            "target":target,
            "scan_type":scan_type,
            "scan_type_label":profile["label"],
            "nse":NSE_OPTIONS[nse_choice]["label"],
            "os_detection_requested":os_detect,
            "generated_at":datetime.now().isoformat(timespec="seconds"),
            "command_display":command,
            "hosts":parsed["hosts"],
            "scan_info":{"nmap_version":parsed["nmap_version"],"args":parsed["nmap_args"]},
            "_severity_counts":parsed["severity_counts"]
        }
        summarize(result)

        history = load_history()
        previous = history[0]["result"] if history else None
        result["comparison"] = compare(result, previous)

        save_history({
            "id":run_id,
            "timestamp":result["generated_at"],
            "target":target,
            "scan_type_label":profile["label"],
            "result":result
        })
        return jsonify(result)

    except FileNotFoundError:
        return jsonify({"status":"error","message":"Nmap is not installed or is not in PATH."}),500
    except subprocess.TimeoutExpired:
        return jsonify({"status":"error","message":"Nmap scan timed out. Try a smaller scan."}),504
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}),500
    finally:
        xml.unlink(missing_ok=True)

@app.route("/history")
def history():
    return jsonify([{
        "id":x.get("id"),
        "timestamp":x.get("timestamp"),
        "target":x.get("target"),
        "scan_type_label":x.get("scan_type_label"),
        "summary":x.get("result",{}).get("summary",{})
    } for x in load_history()])

@app.route("/history/<scan_id>")
def history_detail(scan_id):
    for x in load_history():
        if x.get("id") == scan_id:
            return jsonify(x["result"])
    return jsonify({"status":"error","message":"Scan not found."}),404

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    if not data.get("hosts"):
        return jsonify({"status":"error","message":"No scan result provided."}),400
    path = REPORT_DIR / f"nmap_report_{uuid.uuid4().hex}.pdf"
    try:
        build_pdf_report(data, str(path))
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}),500
    return send_file(path, as_attachment=True, download_name="VulnScanner_Report.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    print("VULNSCANNER — Nmap Security Assessment Platform")
    print("Use only against systems you are authorized to assess.")
    app.run(host="127.0.0.1", port=5001, debug=True)
