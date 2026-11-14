from pathlib import Path
import textwrap

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
PPTX_PATH = ROOT / "presentation" / "ssrf-metadata-protection-proxy.pptx"
PDF_PATH = ROOT / "presentation" / "ssrf-metadata-protection-proxy.pdf"

NAVY = RGBColor(8, 15, 27)
PANEL = RGBColor(17, 29, 46)
PANEL_ALT = RGBColor(21, 39, 57)
TEAL = RGBColor(67, 220, 199)
CYAN = RGBColor(82, 195, 234)
WHITE = RGBColor(235, 243, 249)
MUTED = RGBColor(156, 176, 195)
AMBER = RGBColor(246, 190, 103)
RED = RGBColor(248, 117, 132)

SLIDES = [
    {
        "title": "SSRF Metadata Protection Proxy",
        "kicker": "PROJECT 40 · CLOUD SECURITY",
        "bullets": ["A local, testable defense for metadata access", "Student: Rooman Noori", "MetaGuard · isolated mock-service lab"],
        "notes": "Introduce the project and its safety boundary. This is a local educational simulation: it uses a mock metadata provider and dummy values only, with no production cloud endpoint or credentials.",
    },
    {
        "title": "Cloud Security Context",
        "kicker": "WHY WORKLOAD METADATA MATTERS",
        "bullets": ["Cloud workloads use metadata for identity and configuration.", "A server-side request can cross a trust boundary the browser cannot reach.", "A defensive proxy makes metadata access explicit, narrow, and observable."],
        "notes": "Explain that metadata can contain instance identity and workload identity information. The security objective is to constrain server-side access, not to expose or query real metadata.",
    },
    {
        "title": "What is SSRF?",
        "kicker": "SERVER-SIDE REQUEST FORGERY",
        "bullets": ["An attacker influences a server to request an unintended destination.", "The server may have access to internal-only services.", "Mitigate with exact destination/resource allowlists and by avoiding arbitrary URL fetches."],
        "diagram": ["Untrusted input", "Server request path", "Restricted destination"],
        "notes": "Walk through the conceptual flow: untrusted input reaches a server-side request, which could target a restricted service. The diagram is illustrative only; this project never sends a request to an external or metadata IP.",
    },
    {
        "title": "Metadata Theft Risk",
        "kicker": "A HIGH-VALUE INTERNAL TARGET",
        "bullets": ["Metadata may include instance details and workload identity.", "Temporary credentials can be abused if exposed.", "Network reachability plus weak request validation raises the risk.", "MetaGuard's response: mock-only data, token checks, and audit events."],
        "notes": "Describe impact in general terms and avoid implying all clouds expose identical metadata. All credential-shaped values shown in this lab are marked dummy and cannot authenticate to a provider.",
    },
    {
        "title": "Project Objectives",
        "kicker": "PROJECT 40 · ROOMAN NOORI",
        "bullets": ["Enforce a short-lived IMDSv2-style token workflow.", "Validate method, destination hint, and exact metadata resource.", "Block and record unauthorized requests.", "Provide a React SOC dashboard and repeatable backend tests."],
        "notes": "Summarize the measurable project goals: a protected local service, comprehensible decisions, persistent events, usable monitoring, and reproducible security tests.",
    },
    {
        "title": "Proposed Solution",
        "kicker": "POLICY BEFORE DATA",
        "bullets": ["Client obtains a short-lived token with PUT.", "Proxy validates method → destination → path → token.", "Only an in-process mock provider serves allowlisted fields.", "Every allow/deny result is written to SQLite."],
        "diagram": ["Token", "Policy checks", "Mock data", "SQLite log"],
        "notes": "Explain the request decision order. The proxy does not use a supplied URL as a fetch target; a fixed in-process lookup provides synthetic metadata after validation.",
    },
    {
        "title": "System Architecture",
        "kicker": "LOCAL-ONLY DATA FLOW",
        "bullets": ["React/Vite dashboard communicates with Flask JSON APIs.", "Flask owns all security decisions.", "SQLite stores events, rule state, and test runs.", "The metadata source is a fixed dummy provider; no outbound request exists."],
        "diagram": ["React dashboard\nlocalhost:5173", "Flask API + policy\nlocalhost:5050", "Dummy provider\nin-process", "SQLite\nlocal lab"],
        "notes": "Point out that the browser is not the security boundary. Flask checks each API request. Events and test runs are durable in SQLite; tokens are process-memory state and expire.",
    },
    {
        "title": "Technology Stack",
        "kicker": "SMALL, EXPLAINABLE COMPONENTS",
        "bullets": ["Backend: Python 3, Flask, REST, SQLite.", "Frontend: React 18, Vite 5, JavaScript, responsive CSS.", "Validation: Pytest and an 8-case in-app backend suite.", "Packaging: Dockerfile and loopback-bound Docker Compose."],
        "notes": "Briefly identify the stack and why it fits a self-contained learning project. Docker configuration is provided, but Docker runtime execution depends on Docker Desktop being installed.",
    },
    {
        "title": "Security Implementation",
        "kicker": "DEFENSE IN DEPTH",
        "bullets": ["Secure defaults: token, method, path, destination, SSRF rules enabled.", "Token TTL range is validated; expired/unknown tokens are rejected.", "External destinations are never contacted.", "Blocked events include source, path, method, reason, severity, result, and status."],
        "notes": "Describe each control and emphasize that toggles are intentionally unauthenticated lab controls; the application must not be exposed as a production service. Loopback defaults and no outbound fetch are core constraints.",
    },
    {
        "title": "Live Demonstration",
        "kicker": "REPRODUCIBLE LOCAL SCENARIO",
        "bullets": ["Start Flask and Vite; open the local dashboard.", "Acquire a token and allow a mock region/instance request.", "Try missing/invalid token and an unauthorized destination hint.", "Inspect persisted events and saved test results."],
        "diagram": ["Start local lab", "Allowed request", "Blocked scenarios", "Review audit"],
        "notes": "Run the companion documentation/demo-script.md. Use only loopback URLs. The SSRF test passes a string to policy validation; it does not contact that address.",
    },
    {
        "title": "Testing Results",
        "kicker": "OBSERVED LOCAL VALIDATION",
        "bullets": ["Pytest: 14 passed, 0 failed, 0 skipped.", "Production frontend build: successful.", "In-app security scenarios: 8 of 8 passed.", "Docker runtime: not executed; Docker CLI was unavailable in the environment."],
        "notes": "These results were observed in the local development environment. The in-app run is stored in SQLite. State clearly that Docker Compose was not executed because Docker was not installed/available; do not imply container validation.",
    },
    {
        "title": "Conclusion & Future Scope",
        "kicker": "SAFE BY DESIGN · READY TO DEMONSTRATE",
        "bullets": ["MetaGuard demonstrates a complete local policy, logging, dashboard, and testing loop.", "It is an educational prototype, not a production proxy.", "Future work: authenticated administration, stronger deployment hardening, and isolated integration testing.", "Never connect real metadata endpoints or credentials to this lab."],
        "notes": "Close with the demonstrated outcome and limitations. Suggest future improvements without implying they are implemented. Reiterate that actual cloud integration is out of scope.",
    },
]


def add_text(slide, text, x, y, w, h, size, color, bold=False, font="Aptos"):
    shape = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = shape.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = Inches(0)
    frame.margin_right = Inches(0)
    frame.margin_top = Inches(0)
    frame.margin_bottom = Inches(0)
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    paragraph = frame.paragraphs[0]
    paragraph.text = text
    paragraph.font.name = font
    paragraph.font.size = Pt(size)
    paragraph.font.bold = bold
    paragraph.font.color.rgb = color
    return shape


def add_panel(slide, x, y, w, h, fill=PANEL):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(x),
        Inches(y),
        Inches(w),
        Inches(h),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = RGBColor(41, 63, 83)
    shape.line.width = Pt(0.7)
    return shape


def add_slide_content(prs, item, number):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    background = slide.background.fill
    background.solid()
    background.fore_color.rgb = NAVY

    add_text(slide, "METAGUARD   /   SECURITY LAB", 0.62, 0.27, 5.0, 0.25, 9, TEAL, True)
    add_text(slide, item["kicker"], 0.65, 0.78, 11.6, 0.25, 10, CYAN, True)
    add_text(slide, item["title"], 0.62, 1.08, 12.0, 0.66, 27 if number != 1 else 31, WHITE, True, "Aptos Display")
    slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.65), Inches(1.82), Inches(0.8), Inches(0.035)).fill.solid()
    slide.shapes[-1].fill.fore_color.rgb = TEAL

    if number == 1:
        add_panel(slide, 0.65, 2.45, 7.4, 3.2, PANEL)
        add_text(slide, "A local, testable defense\nfor metadata access", 1.0, 2.9, 6.7, 1.3, 26, WHITE, True, "Aptos Display")
        add_text(slide, "Rooman Noori   ·   Project 40   ·   Cloud Security", 1.02, 4.65, 6.5, 0.45, 14, TEAL, True)
        add_panel(slide, 8.55, 2.45, 4.1, 3.2, PANEL_ALT)
        add_text(slide, "LOCAL LAB", 8.9, 2.9, 3.3, 0.4, 12, TEAL, True)
        add_text(slide, "Mock metadata only\nDummy credentials\nNo outbound requests", 8.9, 3.55, 3.4, 1.5, 18, WHITE, True)
    elif item.get("diagram"):
        diagram_y = 4.6 if len(item["bullets"]) > 3 else 4.4
        card_w = min(2.65, 11.9 / len(item["diagram"]) - 0.25)
        gap = (11.9 - card_w * len(item["diagram"])) / max(len(item["diagram"]) - 1, 1)
        for index, label in enumerate(item["diagram"]):
            x = 0.7 + index * (card_w + gap)
            add_panel(slide, x, diagram_y, card_w, 1.25, PANEL_ALT if index % 2 else PANEL)
            add_text(slide, label, x + 0.12, diagram_y + 0.18, card_w - 0.24, 0.88, 12, TEAL if index == 0 else WHITE, True)
            if index < len(item["diagram"]) - 1:
                add_text(slide, "›", x + card_w + 0.01, diagram_y + 0.34, gap - 0.02, 0.42, 23, CYAN, True)
        bullet_bottom = diagram_y - 0.18
    else:
        bullet_bottom = 6.45

    if number != 1:
        panel_h = min(2.5, 0.52 * len(item["bullets"]) + 0.4)
        add_panel(slide, 0.65, 2.15, 12.0, panel_h)
        top = 2.36
        for index, bullet in enumerate(item["bullets"]):
            y = top + index * 0.49
            add_text(slide, "•", 0.98, y, 0.22, 0.28, 16, TEAL, True)
            add_text(slide, bullet, 1.28, y, 10.95, 0.36, 14, WHITE)

    add_text(slide, "ROOMAN NOORI  ·  PROJECT 40", 0.65, 7.08, 5.5, 0.2, 8, MUTED, True)
    add_text(slide, f"{number:02d} / 12", 11.75, 7.08, 0.9, 0.2, 8, MUTED, True)
    slide.notes_slide.notes_text_frame.text = item["notes"]
    return slide


def create_pptx():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    prs.core_properties.title = "SSRF Metadata Protection Proxy — MetaGuard"
    prs.core_properties.subject = "Project 40 · Cloud Security"
    prs.core_properties.author = "Rooman Noori"
    for number, item in enumerate(SLIDES, 1):
        add_slide_content(prs, item, number)
    prs.save(PPTX_PATH)


def create_pdf():
    page_width, page_height = landscape(letter)
    pdf = canvas.Canvas(str(PDF_PATH), pagesize=(page_width, page_height))
    for number, item in enumerate(SLIDES, 1):
        pdf.setFillColor(colors.HexColor("#080F1B"))
        pdf.rect(0, 0, page_width, page_height, stroke=0, fill=1)
        pdf.setFillColor(colors.HexColor("#43DCC7"))
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(42, page_height - 32, "METAGUARD  /  SECURITY LAB")
        pdf.setFillColor(colors.HexColor("#52C3EA"))
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(42, page_height - 62, item["kicker"])
        pdf.setFillColor(colors.HexColor("#EBF3F9"))
        pdf.setFont("Helvetica-Bold", 23 if number != 1 else 26)
        pdf.drawString(42, page_height - 94, item["title"])
        pdf.setFillColor(colors.HexColor("#43DCC7"))
        pdf.rect(42, page_height - 110, 50, 2, stroke=0, fill=1)

        if number == 1:
            card_y = page_height - 330
            pdf.setFillColor(colors.HexColor("#111D2E"))
            pdf.roundRect(42, card_y, 470, 190, 10, stroke=0, fill=1)
            pdf.setFillColor(colors.HexColor("#EBF3F9"))
            pdf.setFont("Helvetica-Bold", 24)
            pdf.drawString(68, card_y + 128, "A local, testable defense")
            pdf.drawString(68, card_y + 94, "for metadata access")
            pdf.setFillColor(colors.HexColor("#43DCC7"))
            pdf.setFont("Helvetica-Bold", 13)
            pdf.drawString(68, card_y + 45, "Rooman Noori  ·  Project 40  ·  Cloud Security")
            pdf.setFillColor(colors.HexColor("#152739"))
            pdf.roundRect(540, card_y, 210, 190, 10, stroke=0, fill=1)
            pdf.setFillColor(colors.HexColor("#43DCC7"))
            pdf.setFont("Helvetica-Bold", 13)
            pdf.drawString(565, card_y + 145, "LOCAL LAB")
            pdf.setFillColor(colors.HexColor("#EBF3F9"))
            pdf.setFont("Helvetica", 13)
            pdf.drawString(565, card_y + 104, "Mock metadata only")
            pdf.drawString(565, card_y + 78, "Dummy credentials")
            pdf.drawString(565, card_y + 52, "No outbound requests")
        else:
            y = page_height - 145
            pdf.setFillColor(colors.HexColor("#111D2E"))
            pdf.roundRect(42, y - 150, 710, 153, 9, stroke=0, fill=1)
            for index, bullet in enumerate(item["bullets"]):
                line_y = y - 28 - index * 29
                pdf.setFillColor(colors.HexColor("#43DCC7"))
                pdf.circle(60, line_y + 3, 3, stroke=0, fill=1)
                pdf.setFillColor(colors.HexColor("#EBF3F9"))
                pdf.setFont("Helvetica", 12)
                wrapped = textwrap.wrap(bullet, width=94)
                for line_number, line in enumerate(wrapped[:2]):
                    pdf.drawString(74, line_y - line_number * 14, line)
            if item.get("diagram"):
                items = item["diagram"]
                width = 710 / len(items)
                for index, label in enumerate(items):
                    x = 42 + index * width
                    pdf.setFillColor(colors.HexColor("#152739" if index % 2 else "#111D2E"))
                    pdf.roundRect(x, 90, width - 8, 76, 8, stroke=0, fill=1)
                    pdf.setFillColor(colors.HexColor("#8FE8D8" if index == 0 else "#EBF3F9"))
                    pdf.setFont("Helvetica-Bold", 9)
                    lines = label.split("\n")
                    for line_no, line in enumerate(lines[:3]):
                        pdf.drawCentredString(x + (width - 8) / 2, 124 - line_no * 14, line)

        pdf.setFillColor(colors.HexColor("#9CB0C3"))
        pdf.setFont("Helvetica-Bold", 8)
        pdf.drawString(42, 24, "ROOMAN NOORI  ·  PROJECT 40")
        pdf.drawRightString(page_width - 42, 24, f"{number:02d} / 12")
        pdf.showPage()
    pdf.save()


if __name__ == "__main__":
    create_pptx()
    create_pdf()
    print(f"PowerPoint: {PPTX_PATH}")
    print(f"PDF: {PDF_PATH}")
