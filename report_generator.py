"""
Report Generator - Cloud Security Analyzer
Supports: PDF (with charts), CSV, JSON, HTML, XML
"""

import os
import csv
import json
from datetime import datetime


def generate_report(scan, findings, user, fmt, reports_folder):
    os.makedirs(reports_folder, exist_ok=True)
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
    base     = f"CSA_Report_{scan['id']}_{ts}"
    filename = f"{base}.{fmt}"
    filepath = os.path.join(reports_folder, filename)

    if fmt == 'pdf':
        _gen_pdf(scan, findings, user, filepath)
    elif fmt == 'csv':
        _gen_csv(scan, findings, user, filepath)
    elif fmt == 'json':
        _gen_json(scan, findings, user, filepath)
    elif fmt == 'html':
        _gen_html(scan, findings, user, filepath)
    elif fmt == 'xml':
        _gen_xml(scan, findings, user, filepath)
    else:
        raise ValueError(f'Unsupported format: {fmt}')

    return filepath, filename


# ─── PDF ──────────────────────────────────────────────────────────────────────
def _gen_pdf(scan, findings, user, filepath):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, PageBreak)
    from reportlab.graphics.shapes import (Drawing as RLDrawing, Rect, String,
                                           Circle, Wedge, Line, Group)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    # ── Colors ──
    DARK   = colors.HexColor('#1a1a2e')
    ACCENT = colors.HexColor('#0f3460')
    HIGH_C = colors.HexColor('#dc3545')
    MED_C  = colors.HexColor('#fd7e14')
    LOW_C  = colors.HexColor('#28a745')
    INFO_C = colors.HexColor('#0d6efd')
    GREY   = colors.HexColor('#6c757d')
    LIGHT  = colors.HexColor('#f8f9fa')

    doc = SimpleDocTemplate(filepath, pagesize=A4,
                            topMargin=2*cm, bottomMargin=2*cm,
                            leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()

    title_style    = ParagraphStyle('Title2', parent=styles['Title'],
        fontSize=24, textColor=DARK, spaceAfter=4, leading=28)
    subtitle_style = ParagraphStyle('Sub', parent=styles['Normal'],
        fontSize=11, textColor=ACCENT, spaceAfter=4)
    heading_style  = ParagraphStyle('H2', parent=styles['Heading2'],
        fontSize=13, textColor=ACCENT, spaceBefore=10, spaceAfter=5)
    body_style     = ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#333333'), spaceAfter=3, leading=13)
    small_style    = ParagraphStyle('Small', parent=body_style, fontSize=8)
    center_style   = ParagraphStyle('Center', parent=body_style, alignment=TA_CENTER)
    footer_style   = ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=7, textColor=colors.grey, alignment=TA_CENTER)

    story = []

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))

    # Header banner (drawn as a colored table row)
    banner = Table([['☁  Cloud Security Analyzer']], colWidths=[17*cm])
    banner.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), DARK),
        ('TEXTCOLOR',  (0,0), (-1,-1), colors.white),
        ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 18),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING',(0,0),(-1,-1), 14),
        ('LEFTPADDING',(0,0), (-1,-1), 16),
        ('ROUNDEDCORNERS', [6]),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Security Assessment Report", subtitle_style))
    story.append(HRFlowable(width='100%', thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.4*cm))

    meta = [
        ['Scan Name',     scan.get('scan_name') or 'Security Scan'],
        ['Organization',  user.get('organization') or 'N/A'],
        ['Analyst',       user.get('full_name')],
        ['Cloud Provider',scan.get('provider').upper() if scan.get('provider') else 'AWS'],
        ['Scan Date',     scan.get('created_at').replace('T', ' ').split('.')[0] + ' UTC' if isinstance(scan.get('created_at'), str) else scan.get('created_at').strftime('%Y-%m-%d %H:%M UTC')],
        ['Status',        scan.get('status', '').capitalize()],
        ['Risk Score',    f"{scan.get('risk_score')}/100"],
    ]
    meta_t = Table(meta, colWidths=[4.5*cm, 12.5*cm])
    meta_t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (0,-1), colors.HexColor('#e8eaf6')),
        ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 9),
        ('GRID',        (0,0), (-1,-1), 0.4, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS',(1,0),(1,-1),[colors.white, colors.HexColor('#f8f9fa')]),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 0.5*cm))

    # ── EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 0.2*cm))

    # 4 KPI boxes side by side
    high   = scan.get('high_count')   or 0
    medium = scan.get('medium_count') or 0
    low    = scan.get('low_count')    or 0
    total  = scan.get('total_findings') or 0

    kpi_data = [[
        Paragraph(f'<b><font size="22" color="#dc3545">{high}</font></b><br/><font size="8" color="#888">HIGH</font>', center_style),
        Paragraph(f'<b><font size="22" color="#fd7e14">{medium}</font></b><br/><font size="8" color="#888">MEDIUM</font>', center_style),
        Paragraph(f'<b><font size="22" color="#28a745">{low}</font></b><br/><font size="8" color="#888">LOW</font>', center_style),
        Paragraph(f'<b><font size="22" color="#0f3460">{total}</font></b><br/><font size="8" color="#888">TOTAL</font>', center_style),
    ]]
    kpi_t = Table(kpi_data, colWidths=[4.25*cm]*4)
    kpi_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(0,0), colors.HexColor('#ffeaea')),
        ('BACKGROUND', (1,0),(1,0), colors.HexColor('#fff3e0')),
        ('BACKGROUND', (2,0),(2,0), colors.HexColor('#e8f5e9')),
        ('BACKGROUND', (3,0),(3,0), colors.HexColor('#e8eaf6')),
        ('BOX',        (0,0),(-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('INNERGRID',  (0,0),(-1,-1), 0.3, colors.HexColor('#dddddd')),
        ('TOPPADDING', (0,0),(-1,-1), 10),
        ('BOTTOMPADDING',(0,0),(-1,-1), 10),
        ('ALIGN',      (0,0),(-1,-1), 'CENTER'),
        ('VALIGN',     (0,0),(-1,-1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(kpi_t)
    story.append(Spacer(1, 0.5*cm))

    # ── PIE CHART ──────────────────────────────────────────────────────────
    story.append(Paragraph("Severity Distribution — Visual Overview", heading_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 0.3*cm))

    # Build pie + bar charts side by side using ReportLab drawing
    from reportlab.graphics.shapes import Drawing as D, Wedge, Rect, String, Line
    import math

    # ── Pie Chart (left) ──
    pie_w, pie_h = 200, 180
    pie_d = D(pie_w, pie_h)

    cx, cy, radius = 90, 90, 70
    slices = []
    if total > 0:
        slices = [
            (high,   HIGH_C, 'High'),
            (medium, MED_C,  'Medium'),
            (low,    LOW_C,  'Low'),
        ]
    else:
        slices = [(1, GREY, 'No Data')]

    start_angle = 90.0
    total_for_chart = sum(s[0] for s in slices) or 1

    for count, clr, label in slices:
        if count == 0:
            continue
        sweep = 360.0 * count / total_for_chart
        w = Wedge(cx, cy, radius, start_angle, start_angle + sweep,
                  fillColor=clr, strokeColor=colors.white, strokeWidth=1.5)
        pie_d.add(w)
        # label angle midpoint
        mid = math.radians(start_angle + sweep / 2)
        lx = cx + (radius * 0.65) * math.cos(mid)
        ly = cy + (radius * 0.65) * math.sin(mid)
        if count > 0 and total > 0:
            pct = int(round(count / total_for_chart * 100))
            pie_d.add(String(lx, ly - 4, f'{pct}%',
                             fontSize=8, fillColor=colors.white,
                             textAnchor='middle', fontName='Helvetica-Bold'))
        start_angle += sweep

    # Legend for pie
    leg_items = [
        (HIGH_C, f'High ({high})'),
        (MED_C,  f'Medium ({medium})'),
        (LOW_C,  f'Low ({low})'),
    ]
    for i, (clr, txt) in enumerate(leg_items):
        y_pos = 160 - i * 18
        pie_d.add(Rect(150, y_pos, 12, 10, fillColor=clr, strokeColor=None))
        pie_d.add(String(168, y_pos + 1, txt, fontSize=8,
                         fillColor=colors.HexColor('#333333'), textAnchor='start'))

    pie_d.add(String(cx, 5, 'Severity Breakdown', fontSize=8,
                     fillColor=colors.grey, textAnchor='middle'))

    # ── Bar Chart (right) ──
    bar_w, bar_h = 220, 180
    bar_d = D(bar_w, bar_h)

    bars = [
        ('High',   high,   HIGH_C),
        ('Medium', medium, MED_C),
        ('Low',    low,    LOW_C),
    ]
    max_val = max(high, medium, low, 1)
    bar_width = 38
    spacing = 20
    chart_h = 130
    x_start = 30
    y_base  = 30

    # Y-axis
    bar_d.add(Line(x_start, y_base, x_start, y_base + chart_h,
                   strokeColor=colors.HexColor('#cccccc'), strokeWidth=0.5))
    # X-axis
    bar_d.add(Line(x_start, y_base, x_start + (bar_width + spacing) * 3 + 10, y_base,
                   strokeColor=colors.HexColor('#cccccc'), strokeWidth=0.5))

    for i, (label, val, clr) in enumerate(bars):
        x = x_start + 10 + i * (bar_width + spacing)
        bar_height = int((val / max_val) * chart_h) if max_val > 0 else 2
        bar_height = max(bar_height, 2)

        # Bar shadow
        bar_d.add(Rect(x + 2, y_base - 2, bar_width, bar_height,
                       fillColor=colors.HexColor('#dddddd'), strokeColor=None))
        # Bar fill
        bar_d.add(Rect(x, y_base, bar_width, bar_height,
                       fillColor=clr, strokeColor=None, rx=3, ry=3))
        # Value on top
        bar_d.add(String(x + bar_width / 2, y_base + bar_height + 3, str(val),
                         fontSize=9, fillColor=colors.HexColor('#333333'),
                         textAnchor='middle', fontName='Helvetica-Bold'))
        # X label
        bar_d.add(String(x + bar_width / 2, y_base - 12, label,
                         fontSize=8, fillColor=colors.HexColor('#555555'),
                         textAnchor='middle'))

    bar_d.add(String(x_start + 80, y_base + chart_h + 8, 'Finding Count by Severity',
                     fontSize=8, fillColor=colors.grey, textAnchor='middle'))

    # Put charts side by side
    charts_row = Table([[pie_d, bar_d]], colWidths=[9*cm, 9*cm])
    charts_row.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',(0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#eeeeee')),
        ('BACKGROUND', (0,0),(-1,-1), colors.HexColor('#fafafa')),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(charts_row)
    story.append(Spacer(1, 0.5*cm))

    # ── Compliance bar chart (horizontal) ──
    if findings:
        from collections import Counter
        compliance_data = Counter()
        for f in findings:
            if f.get('compliance'):
                for tag in f.get('compliance').split('|'):
                    tag = tag.strip()
                    if tag:
                        compliance_data[tag] += 1

        if compliance_data:
            story.append(Paragraph("Compliance Framework Coverage", heading_style))
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            story.append(Spacer(1, 0.2*cm))

            comp_items = compliance_data.most_common(6)
            comp_max = comp_items[0][1] if comp_items else 1
            comp_colors = [INFO_C, ACCENT, colors.HexColor('#6f42c1'),
                           colors.HexColor('#20c997'), HIGH_C, MED_C]

            comp_rows = [['Framework', 'Findings', 'Coverage']]
            for i, (tag, cnt) in enumerate(comp_items):
                bar_pct = int(cnt / comp_max * 100)
                clr = comp_colors[i % len(comp_colors)]
                bar_cell = Table([['']], colWidths=[bar_pct * 0.08 * cm + 0.1])
                bar_cell.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(-1,-1), clr),
                    ('TOPPADDING', (0,0),(-1,-1), 5),
                    ('BOTTOMPADDING',(0,0),(-1,-1), 5),
                ]))
                comp_rows.append([
                    Paragraph(f'<b>{tag}</b>', body_style),
                    Paragraph(f'<b><font color="{clr.hexval() if hasattr(clr,"hexval") else "#0d6efd"}">{cnt}</font></b>', center_style),
                    bar_cell,
                ])

            comp_t = Table(comp_rows, colWidths=[4*cm, 2*cm, 11*cm])
            comp_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), DARK),
                ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
                ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',   (0,0), (-1,-1), 8),
                ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#eeeeee')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING',(0,0),(-1,-1), 4),
                ('LEFTPADDING',(0,0), (-1,-1), 8),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            story.append(comp_t)
            story.append(Spacer(1, 0.5*cm))

    story.append(PageBreak())

    # ── DETAILED FINDINGS ──────────────────────────────────────────────────
    story.append(Paragraph("Detailed Security Findings", heading_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 0.2*cm))

    if not findings:
        story.append(Paragraph(
            "✅ No security issues found! Your cloud environment is well-configured.",
            body_style))
    else:
        sev_order = {'High': 0, 'Medium': 1, 'Low': 2}
        sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get('severity'), 3))

        for i, f in enumerate(sorted_findings, 1):
            sev_color = HIGH_C if f.get('severity') == 'High' else (MED_C if f.get('severity') == 'Medium' else LOW_C)
            sev_bg    = colors.HexColor('#ffeaea' if f.get('severity') == 'High' else
                                        ('#fff3e0' if f.get('severity') == 'Medium' else '#e8f5e9'))

            # Finding header
            hdr = Table([[
                Paragraph(f'<b>#{i}. {f.get("check_name")}</b>', body_style),
                Paragraph(f'<font color="{sev_color.hexval() if hasattr(sev_color,"hexval") else "#dc3545"}"><b>{f.get("severity")}</b></font>',
                          ParagraphStyle('sev', parent=body_style, alignment=TA_RIGHT)),
            ]], colWidths=[13.5*cm, 3*cm])
            hdr.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), colors.HexColor('#eef2ff')),
                ('TOPPADDING', (0,0),(-1,-1), 5),
                ('BOTTOMPADDING',(0,0),(-1,-1), 4),
                ('LEFTPADDING',(0,0),(-1,-1), 8),
                ('LINEBELOW', (0,0),(-1,-1), 1.5, sev_color),
            ]))
            story.append(hdr)

            detail = [
                ['Resource',       f"{f.get('resource_type')} / {f.get('resource_id')}"],
                ['Compliance',     f.get('compliance') or 'N/A'],
                ['Description',    f.get('description') or ''],
                ['Recommendation', f.get('recommendation') or ''],
            ]
            det_t = Table(detail, colWidths=[3.5*cm, 13.5*cm])
            det_t.setStyle(TableStyle([
                ('FONTNAME',   (0,0),(0,-1), 'Helvetica-Bold'),
                ('FONTSIZE',   (0,0),(-1,-1), 8),
                ('GRID',       (0,0),(-1,-1), 0.3, colors.HexColor('#dddddd')),
                ('TOPPADDING', (0,0),(-1,-1), 3),
                ('BOTTOMPADDING',(0,0),(-1,-1), 3),
                ('LEFTPADDING',(0,0),(-1,-1), 8),
                ('BACKGROUND', (0,0),(0,-1), colors.HexColor('#f4f6f9')),
                ('BACKGROUND', (0,3),(1,3), colors.HexColor('#f0f7ff')),
            ]))
            story.append(det_t)
            story.append(Spacer(1, 0.25*cm))

    # ── FOOTER ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#cccccc')))
    story.append(Paragraph(
        f"Generated by Cloud Security Analyzer (CSA)  |  "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')} UTC  |  University of Wah FYP",
        footer_style))

    doc.build(story)


# ─── CSV ──────────────────────────────────────────────────────────────────────
def _gen_csv(scan, findings, user, filepath):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Scan Name', 'Scan Date', 'Organization', 'Provider',
            'Risk Score', '#', 'Severity', 'Resource Type', 'Resource ID',
            'Check Name', 'Description', 'Recommendation', 'Compliance', 'Status'
        ])
        for i, finding in enumerate(findings, 1):
            writer.writerow([
                scan.get('scan_name'), scan.get('created_at', '').replace('T', ' ').split('.')[0] + ' UTC' if isinstance(scan.get('created_at'), str) else scan.get('created_at').strftime('%Y-%m-%d %H:%M'),
                user.get('organization') or '', scan.get('provider') or 'AWS',
                scan.get('risk_score'), i,
                finding.get('severity'), finding.get('resource_type'), finding.get('resource_id'),
                finding.get('check_name'), finding.get('description'),
                finding.get('recommendation'), finding.get('compliance') or '', finding.get('status')
            ])


# ─── JSON ─────────────────────────────────────────────────────────────────────
def _gen_json(scan, findings, user, filepath):
    data = {
        'report_metadata': {
            'tool':         'Cloud Security Analyzer (CSA)',
            'version':      '2.0.0',
            'generated_at': datetime.now().isoformat(),
            'organization': user.get('organization'),
            'analyst':      user.get('full_name'),
        },
        'scan_summary': {
            'scan_id':        scan.get('id'),
            'scan_name':      scan.get('scan_name'),
            'provider':       scan.get('provider'),
            'status':         scan.get('status'),
            'scan_date':      scan.get('created_at') if isinstance(scan.get('created_at'), str) else scan.get('created_at').isoformat() if scan.get('created_at') else None,
            'total_findings': scan.get('total_findings'),
            'high_count':     scan.get('high_count'),
            'medium_count':   scan.get('medium_count'),
            'low_count':      scan.get('low_count'),
            'risk_score':     scan.get('risk_score'),
        },
        'findings': [
            {
                'id':             f.get('id'),
                'severity':       f.get('severity'),
                'resource_type':  f.get('resource_type'),
                'resource_id':    f.get('resource_id'),
                'check_name':     f.get('check_name'),
                'description':    f.get('description'),
                'recommendation': f.get('recommendation'),
                'compliance':     f.get('compliance'),
                'status':         f.get('status'),
                'detected_at':    f.get('created_at') if isinstance(f.get('created_at'), str) else f.get('created_at').isoformat() if f.get('created_at') else None,
            }
            for f in findings
        ]
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)


# ─── HTML ─────────────────────────────────────────────────────────────────────
def _gen_html(scan, findings, user, filepath):
    def sev_color(s):
        return {'Critical': '#ff4040', 'High': '#f85149', 'Medium': '#d29922', 'Low': '#3fb950'}.get(s, '#8b949e')
    def sev_bg(s):
        return {'Critical': 'rgba(255,64,64,.12)', 'High': 'rgba(248,81,73,.12)', 'Medium': 'rgba(210,153,34,.12)', 'Low': 'rgba(63,185,80,.12)'}.get(s, 'rgba(139,148,158,.1)')

    high   = scan.get('high_count')   or 0
    medium = scan.get('medium_count') or 0
    low    = scan.get('low_count')    or 0
    total  = scan.get('total_findings') or 0
    crit   = scan.get('critical_count') or 0

    import math
    slices_data = [('Critical', crit, '#ff4040'), ('High', high, '#f85149'), ('Medium', medium, '#d29922'), ('Low', low, '#3fb950')]
    pie_svg = _build_pie_svg_dark(slices_data, total)
    bar_svg = _build_bar_svg_dark(slices_data)

    findings_html = ''
    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get('severity'), 4))
    for i, f in enumerate(sorted_findings, 1):
        findings_html += f"""
        <div style="border-left:3px solid {sev_color(f.get('severity'))};background:{sev_bg(f.get('severity'))};padding:14px 18px;margin-bottom:12px;border-radius:6px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <strong style="font-size:14px;color:#e6edf3;">#{i}. {f.get('check_name')}</strong>
            <span style="background:{sev_color(f.get('severity'))};color:white;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:.3px;">{f.get('severity')}</span>
          </div>
          <table style="width:100%;font-size:12px;border-collapse:collapse;">
            <tr><td style="width:120px;font-weight:600;padding:4px 0;color:#8b949e;vertical-align:top;">Resource</td><td style="color:#c9d1d9;">{f.get('resource_type')} / <code style="background:#21262d;padding:1px 6px;border-radius:3px;font-size:11px;color:#58a6ff;">{f.get('resource_id')}</code></td></tr>
            <tr><td style="font-weight:600;padding:4px 0;color:#8b949e;">Compliance</td><td style="color:#c9d1d9;">{f.get('compliance') or 'N/A'}</td></tr>
            <tr><td style="font-weight:600;padding:4px 0;color:#8b949e;vertical-align:top;">Issue</td><td style="color:#c9d1d9;line-height:1.5;">{f.get('description')}</td></tr>
            <tr><td style="font-weight:600;padding:4px 0;color:#8b949e;vertical-align:top;">🔧 Fix</td><td style="color:#58a6ff;line-height:1.5;">{f.get('recommendation')}</td></tr>
          </table>
        </div>"""

    score = scan.get('risk_score') or 0
    score_color = '#3fb950' if score >= 80 else ('#58a6ff' if score >= 70 else ('#d29922' if score >= 50 else '#f85149'))

    scan_date = scan.get('created_at')
    if isinstance(scan_date, str):
        scan_date_fmt = scan_date.replace('T', ' ').split('.')[0] + ' UTC'
    else:
        scan_date_fmt = scan_date.strftime('%Y-%m-%d %H:%M UTC') if scan_date else 'N/A'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSA Security Report — {scan.get('scan_name')}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  * {{box-sizing:border-box;margin:0;padding:0}}
  body {{font-family:'Inter',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;}}
  .header {{background:linear-gradient(135deg,#0d1117 0%,#0f3460 50%,#1a1a2e 100%);padding:40px 48px;position:relative;overflow:hidden;}}
  .header::before {{content:'';position:absolute;top:-80px;right:-80px;width:300px;height:300px;border-radius:50%;background:radial-gradient(circle,rgba(88,166,255,.12),transparent 70%);}}
  .header .shield {{font-size:32px;margin-bottom:8px;text-shadow:0 0 20px rgba(88,166,255,.4);}}
  .header h1 {{font-size:28px;font-weight:800;margin-bottom:4px;}}
  .header h1 span {{color:#58a6ff;}}
  .header p {{font-size:13px;color:#8b949e;}}
  .container {{max-width:1000px;margin:0 auto;padding:28px 24px;}}
  .card {{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:20px;}}
  .card h2 {{font-size:16px;font-weight:700;color:#e6edf3;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:8px;}}
  .kpi-row {{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px;}}
  .kpi {{background:#161b22;border:1px solid #30363d;border-radius:10px;text-align:center;padding:20px 16px;border-top:3px solid transparent;}}
  .kpi .num {{font-size:32px;font-weight:800;line-height:1;}}
  .kpi .lbl {{font-size:11px;margin-top:6px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;}}
  .meta-grid {{display:grid;grid-template-columns:1fr 1fr;gap:10px;}}
  .meta-item {{background:#21262d;padding:12px 16px;border-radius:8px;border:1px solid #30363d;}}
  .meta-item label {{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:4px;}}
  .meta-item span {{font-size:14px;font-weight:600;color:#e6edf3;}}
  .charts-row {{display:grid;grid-template-columns:1fr 1fr;gap:20px;}}
  .score-badge {{display:inline-flex;align-items:center;gap:8px;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid;}}
  code {{font-family:'JetBrains Mono',monospace;}}
  footer {{text-align:center;color:#484f58;font-size:11px;padding:24px;border-top:1px solid #21262d;margin-top:16px;}}
  footer span {{color:#58a6ff;}}
</style>
</head>
<body>
<div class="header">
  <div class="shield">🛡</div>
  <h1>Cloud Security <span>Analyzer</span></h1>
  <p>Security Assessment Report &nbsp;|&nbsp; {scan.get('scan_name')} &nbsp;|&nbsp; {scan_date_fmt}</p>
</div>
<div class="container">
  <div class="kpi-row">
    <div class="kpi" style="border-top-color:#ff4040;"><div class="num" style="color:#ff4040;">{crit}</div><div class="lbl">Critical</div></div>
    <div class="kpi" style="border-top-color:#f85149;"><div class="num" style="color:#f85149;">{high}</div><div class="lbl">High</div></div>
    <div class="kpi" style="border-top-color:#d29922;"><div class="num" style="color:#d29922;">{medium}</div><div class="lbl">Medium</div></div>
    <div class="kpi" style="border-top-color:#3fb950;"><div class="num" style="color:#3fb950;">{low}</div><div class="lbl">Low</div></div>
  </div>

  <div class="card">
    <h2>📊 Severity Analysis</h2>
    <div class="charts-row">
      {pie_svg}
      {bar_svg}
    </div>
  </div>

  <div class="card">
    <h2>📋 Scan Information</h2>
    <div class="meta-grid">
      <div class="meta-item"><label>Scan Name</label><span>{scan.get('scan_name')}</span></div>
      <div class="meta-item"><label>Organization</label><span>{user.get('organization') or 'N/A'}</span></div>
      <div class="meta-item"><label>Analyst</label><span>{user.get('full_name')}</span></div>
      <div class="meta-item"><label>Cloud Provider</label><span>{(scan.get('provider') or 'AWS').upper()}</span></div>
      <div class="meta-item"><label>Scan Date</label><span>{scan_date_fmt}</span></div>
      <div class="meta-item"><label>Risk Score</label><span style="color:{score_color};">{score}/100</span></div>
    </div>
  </div>

  <div class="card">
    <h2>🔍 Detailed Findings ({len(sorted_findings)})</h2>
    {findings_html if findings_html else '<p style="color:#3fb950;font-size:15px;text-align:center;padding:20px;">✅ No security issues detected. Your cloud environment is well-configured.</p>'}
  </div>
</div>
<footer>Generated by <span>Cloud Security Analyzer (CSA)</span> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC &nbsp;|&nbsp; University of Wah FYP</footer>
</body></html>"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)


def _build_pie_svg(slices_data, total):
    """Build a donut chart SVG for HTML reports (light theme — used by old code)"""
    import math
    cx, cy, ro, ri = 100, 100, 75, 40
    svg = f'<div style="text-align:center;"><svg width="200" height="220" viewBox="0 0 200 220">'
    svg += f'<text x="100" y="14" text-anchor="middle" font-size="12" font-weight="600" fill="#333">Severity Pie</text>'

    if total == 0:
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ro}" fill="#eee" stroke="white" stroke-width="2"/>'
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ri}" fill="white"/>'
        svg += f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="12" fill="#aaa">No Data</text>'
    else:
        start = -90.0
        valid = [(l, c, col) for l, c, col in slices_data if c > 0]
        for label, count, color in valid:
            pct = count / total
            sweep = 360 * pct
            end = start + sweep
            sr, er = math.radians(start), math.radians(end)
            x1o = cx + ro * math.cos(sr); y1o = (cy+10) + ro * math.sin(sr)
            x2o = cx + ro * math.cos(er); y2o = (cy+10) + ro * math.sin(er)
            x1i = cx + ri * math.cos(er); y1i = (cy+10) + ri * math.sin(er)
            x2i = cx + ri * math.cos(sr); y2i = (cy+10) + ri * math.sin(sr)
            large = 1 if sweep > 180 else 0
            path = (f'M {x1o:.1f} {y1o:.1f} '
                    f'A {ro} {ro} 0 {large} 1 {x2o:.1f} {y2o:.1f} '
                    f'L {x1i:.1f} {y1i:.1f} '
                    f'A {ri} {ri} 0 {large} 0 {x2i:.1f} {y2i:.1f} Z')
            svg += f'<path d="{path}" fill="{color}" stroke="white" stroke-width="2"/>'
            mid = math.radians(start + sweep / 2)
            lx = cx + (ro + ri) / 2 * math.cos(mid)
            ly = (cy+10) + (ro + ri) / 2 * math.sin(mid)
            pct_str = f'{int(round(pct*100))}%'
            svg += f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="white">{pct_str}</text>'
            start = end

    # Legend
    legend_y = (cy + 10) + ro + 20
    for i, (label, count, color) in enumerate(slices_data):
        lx = 20 + i * 65
        svg += f'<rect x="{lx}" y="{legend_y}" width="12" height="10" fill="{color}" rx="2"/>'
        svg += f'<text x="{lx+15}" y="{legend_y+9}" font-size="10" fill="#555">{label} ({count})</text>'

    svg += '</svg></div>'
    return svg


def _build_bar_svg(slices_data):
    """Build a bar chart SVG for HTML reports (light theme — used by old code)"""
    svg = '<div style="text-align:center;"><svg width="240" height="220" viewBox="0 0 240 220">'
    svg += '<text x="120" y="14" text-anchor="middle" font-size="12" font-weight="600" fill="#333">Severity Bar Chart</text>'

    max_val = max((c for _, c, _ in slices_data), default=1)
    max_val = max(max_val, 1)
    chart_top = 30
    chart_bottom = 170
    chart_h = chart_bottom - chart_top
    bar_w = 45
    gap = 25
    x_start = 30

    for g in range(0, 5):
        gy = chart_bottom - (g / 4) * chart_h
        svg += f'<line x1="{x_start}" y1="{gy:.0f}" x2="220" y2="{gy:.0f}" stroke="#eee" stroke-width="1"/>'
        val_label = int(max_val * g / 4)
        svg += f'<text x="{x_start-4}" y="{gy+4:.0f}" text-anchor="end" font-size="8" fill="#aaa">{val_label}</text>'

    for i, (label, count, color) in enumerate(slices_data):
        bx = x_start + 15 + i * (bar_w + gap)
        bh = int((count / max_val) * chart_h) if max_val else 0
        by = chart_bottom - bh
        svg += f'<rect x="{bx}" y="{by}" width="{bar_w}" height="{bh}" fill="{color}" rx="4" opacity="0.9"/>'
        svg += f'<text x="{bx + bar_w/2:.0f}" y="{by-4}" text-anchor="middle" font-size="10" font-weight="700" fill="{color}">{count}</text>'
        svg += f'<text x="{bx + bar_w/2:.0f}" y="{chart_bottom+14}" text-anchor="middle" font-size="10" fill="#555">{label}</text>'

    svg += f'<line x1="{x_start}" y1="{chart_top}" x2="{x_start}" y2="{chart_bottom}" stroke="#ccc" stroke-width="1"/>'
    svg += f'<line x1="{x_start}" y1="{chart_bottom}" x2="220" y2="{chart_bottom}" stroke="#ccc" stroke-width="1"/>'

    svg += '</svg></div>'
    return svg


# ─── Dark-themed SVG charts for HTML report ───────────────────────────────────
def _build_pie_svg_dark(slices_data, total):
    """Build a dark-themed donut chart SVG"""
    import math
    cx, cy, ro, ri = 100, 100, 75, 40
    svg = f'<div style="text-align:center;"><svg width="200" height="220" viewBox="0 0 200 220">'
    svg += f'<text x="100" y="14" text-anchor="middle" font-size="12" font-weight="600" fill="#e6edf3">Severity Distribution</text>'

    if total == 0:
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ro}" fill="#21262d" stroke="#30363d" stroke-width="2"/>'
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ri}" fill="#161b22"/>'
        svg += f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="12" fill="#8b949e">No Data</text>'
    else:
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ro}" fill="#21262d"/>'
        start = -90.0
        valid = [(l, c, col) for l, c, col in slices_data if c > 0]
        for label, count, color in valid:
            pct = count / total
            sweep = 360 * pct
            end = start + sweep
            sr, er = math.radians(start), math.radians(end)
            x1o = cx + ro * math.cos(sr); y1o = (cy+10) + ro * math.sin(sr)
            x2o = cx + ro * math.cos(er); y2o = (cy+10) + ro * math.sin(er)
            x1i = cx + ri * math.cos(er); y1i = (cy+10) + ri * math.sin(er)
            x2i = cx + ri * math.cos(sr); y2i = (cy+10) + ri * math.sin(sr)
            large = 1 if sweep > 180 else 0
            path = (f'M {x1o:.1f} {y1o:.1f} '
                    f'A {ro} {ro} 0 {large} 1 {x2o:.1f} {y2o:.1f} '
                    f'L {x1i:.1f} {y1i:.1f} '
                    f'A {ri} {ri} 0 {large} 0 {x2i:.1f} {y2i:.1f} Z')
            svg += f'<path d="{path}" fill="{color}" stroke="#0d1117" stroke-width="2"/>'
            mid = math.radians(start + sweep / 2)
            lx = cx + (ro + ri) / 2 * math.cos(mid)
            ly = (cy+10) + (ro + ri) / 2 * math.sin(mid)
            pct_str = f'{int(round(pct*100))}%'
            svg += f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="white">{pct_str}</text>'
            start = end
        svg += f'<circle cx="{cx}" cy="{cy+10}" r="{ri}" fill="#161b22"/>'
        svg += f'<text x="{cx}" y="{cy+7}" text-anchor="middle" font-size="18" font-weight="800" fill="#e6edf3">{total}</text>'
        svg += f'<text x="{cx}" y="{cy+20}" text-anchor="middle" font-size="8" fill="#8b949e" letter-spacing="1">FINDINGS</text>'

    legend_y = (cy + 10) + ro + 18
    for i, (label, count, color) in enumerate(slices_data):
        lx = 10 + i * 50
        svg += f'<rect x="{lx}" y="{legend_y}" width="10" height="8" fill="{color}" rx="2"/>'
        svg += f'<text x="{lx+13}" y="{legend_y+8}" font-size="9" fill="#8b949e">{label} ({count})</text>'

    svg += '</svg></div>'
    return svg


def _build_bar_svg_dark(slices_data):
    """Build a dark-themed bar chart SVG"""
    svg = '<div style="text-align:center;"><svg width="260" height="220" viewBox="0 0 260 220">'
    svg += '<text x="130" y="14" text-anchor="middle" font-size="12" font-weight="600" fill="#e6edf3">Finding Count</text>'

    max_val = max((c for _, c, _ in slices_data), default=1)
    max_val = max(max_val, 1)
    chart_top = 30
    chart_bottom = 175
    chart_h = chart_bottom - chart_top
    bar_w = 38
    gap = 18
    x_start = 30

    for g in range(0, 5):
        gy = chart_bottom - (g / 4) * chart_h
        svg += f'<line x1="{x_start}" y1="{gy:.0f}" x2="240" y2="{gy:.0f}" stroke="#21262d" stroke-width="1"/>'
        val_label = int(max_val * g / 4)
        svg += f'<text x="{x_start-4}" y="{gy+4:.0f}" text-anchor="end" font-size="8" fill="#484f58">{val_label}</text>'

    for i, (label, count, color) in enumerate(slices_data):
        bx = x_start + 12 + i * (bar_w + gap)
        bh = int((count / max_val) * chart_h) if max_val else 0
        by = chart_bottom - bh
        svg += f'<rect x="{bx}" y="{by}" width="{bar_w}" height="{bh}" fill="{color}" rx="4" opacity="0.85"/>'
        svg += f'<text x="{bx + bar_w/2:.0f}" y="{by-5}" text-anchor="middle" font-size="11" font-weight="700" fill="{color}">{count}</text>'
        svg += f'<text x="{bx + bar_w/2:.0f}" y="{chart_bottom+14}" text-anchor="middle" font-size="9" fill="#8b949e">{label}</text>'

    svg += f'<line x1="{x_start}" y1="{chart_top}" x2="{x_start}" y2="{chart_bottom}" stroke="#30363d" stroke-width="1"/>'
    svg += f'<line x1="{x_start}" y1="{chart_bottom}" x2="240" y2="{chart_bottom}" stroke="#30363d" stroke-width="1"/>'

    svg += '</svg></div>'
    return svg


# ─── XML ──────────────────────────────────────────────────────────────────────
def _gen_xml(scan, findings, user, filepath):
    """Generate XML report with structured security data"""
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.dom.minidom import parseString

    root = Element('SecurityReport')
    root.set('xmlns', 'https://csa.uow.edu.pk/report/v2')
    root.set('generated', datetime.now().isoformat())

    # Metadata
    meta = SubElement(root, 'Metadata')
    SubElement(meta, 'Tool').text = 'Cloud Security Analyzer (CSA)'
    SubElement(meta, 'Version').text = '2.0.0'
    SubElement(meta, 'Organization').text = user.get('organization') or 'N/A'
    SubElement(meta, 'Analyst').text = user.get('full_name') or 'N/A'
    SubElement(meta, 'University').text = 'University of Wah'

    # Scan summary
    summary = SubElement(root, 'ScanSummary')
    SubElement(summary, 'ScanID').text = str(scan.get('id'))
    SubElement(summary, 'ScanName').text = scan.get('scan_name') or 'Security Scan'
    SubElement(summary, 'Provider').text = (scan.get('provider') or 'AWS').upper()
    SubElement(summary, 'Status').text = scan.get('status') or 'completed'
    scan_date = scan.get('created_at')
    if isinstance(scan_date, str):
        SubElement(summary, 'ScanDate').text = scan_date
    elif scan_date:
        SubElement(summary, 'ScanDate').text = scan_date.isoformat()
    SubElement(summary, 'Categories').text = scan.get('categories') or 'all'

    # Risk assessment
    risk = SubElement(summary, 'RiskAssessment')
    SubElement(risk, 'RiskScore').text = str(scan.get('risk_score') or 0)
    SubElement(risk, 'TotalFindings').text = str(scan.get('total_findings') or 0)
    SubElement(risk, 'CriticalCount').text = str(scan.get('critical_count') or 0)
    SubElement(risk, 'HighCount').text = str(scan.get('high_count') or 0)
    SubElement(risk, 'MediumCount').text = str(scan.get('medium_count') or 0)
    SubElement(risk, 'LowCount').text = str(scan.get('low_count') or 0)

    # Findings
    findings_el = SubElement(root, 'Findings', count=str(len(findings)))
    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get('severity'), 4))

    for i, f in enumerate(sorted_findings, 1):
        finding = SubElement(findings_el, 'Finding', id=str(i))
        SubElement(finding, 'Severity').text = f.get('severity') or 'Low'
        SubElement(finding, 'ResourceType').text = f.get('resource_type') or ''
        SubElement(finding, 'ResourceID').text = f.get('resource_id') or ''
        SubElement(finding, 'CheckName').text = f.get('check_name') or ''
        SubElement(finding, 'Description').text = f.get('description') or ''
        SubElement(finding, 'Recommendation').text = f.get('recommendation') or ''
        SubElement(finding, 'Compliance').text = f.get('compliance') or 'N/A'
        SubElement(finding, 'Status').text = f.get('status') or 'open'
        if f.get('created_at'):
            detected = f.get('created_at')
            SubElement(finding, 'DetectedAt').text = detected if isinstance(detected, str) else detected.isoformat()

    # Pretty print XML
    rough = tostring(root, encoding='unicode')
    pretty = parseString(rough).toprettyxml(indent='  ', encoding=None)
    # Remove extra XML declaration if present
    lines = pretty.split('\n')
    if lines and lines[0].startswith('<?xml'):
        lines[0] = '<?xml version="1.0" encoding="UTF-8"?>'

    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))
