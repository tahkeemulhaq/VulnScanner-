from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import mm

def build_pdf_report(data, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=14*mm, leftMargin=14*mm, topMargin=14*mm, bottomMargin=14*mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title2", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#00a85a"))
    story = [
        Paragraph("VULNSCANNER — NMAP SECURITY ASSESSMENT", title),
        Spacer(1, 8),
        Paragraph(f"<b>Target:</b> {data.get('target','')}", styles["BodyText"]),
        Paragraph(f"<b>Scan:</b> {data.get('scan_type_label','')}", styles["BodyText"]),
        Paragraph(f"<b>Generated:</b> {data.get('generated_at','')}", styles["BodyText"]),
        Spacer(1, 10),
    ]
    s = data.get("summary", {})
    rows = [
        ["Metric","Value"],
        ["Hosts Up", str(s.get("hosts_up",0))],
        ["Open Ports", str(s.get("open_ports",0))],
        ["NSE Results", str(s.get("scripts_run",0))],
        ["Findings", str(s.get("findings_total",0))],
        ["Risk", f'{s.get("risk",{}).get("score",0)}/100 — {s.get("risk",{}).get("label","LOW")}'],
    ]
    t = Table(rows, colWidths=[70*mm,100*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0b2018")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.HexColor("#18d887")),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#cccccc")),
        ("PADDING",(0,0),(-1,-1),7),
    ]))
    story += [t, Spacer(1,12)]

    for host in data.get("hosts", []):
        story.append(Paragraph(f"<b>Host:</b> {host.get('address','')} — {host.get('status','')}", styles["Heading2"]))
        story.append(Paragraph(f"OS: {host.get('os','Not detected')} {host.get('os_confidence','') or ''}", styles["BodyText"]))
        port_rows = [["Port","State","Service","Product / Version"]]
        for p in host.get("ports",[]):
            sv = p.get("service",{})
            port_rows.append([
                f'{p.get("port")}/{p.get("protocol")}',
                p.get("state",""),
                sv.get("name",""),
                " ".join(x for x in [sv.get("product",""),sv.get("version",""),sv.get("extra","")] if x)
            ])
        pt = Table(port_rows, colWidths=[30*mm,25*mm,35*mm,80*mm])
        pt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),
            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#bbbbbb")),
            ("PADDING",(0,0),(-1,-1),5),
        ]))
        story += [pt, Spacer(1,8)]
        for finding in host.get("findings",[]):
            story.append(Paragraph(
                f"<b>{finding.get('script','')}</b> — {finding.get('severity','info').upper()}<br/>{finding.get('output','')[:1800]}",
                styles["BodyText"]
            ))
            story.append(Spacer(1,6))
    doc.build(story)
