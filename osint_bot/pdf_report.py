from __future__ import annotations

import re
from pathlib import Path


def write_pdf_from_markdown(markdown_path: Path, pdf_path: Path | None = None) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_RIGHT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise RuntimeError("Export PDF non disponibile: installa il pacchetto reportlab.") from exc

    pdf_path = pdf_path or markdown_path.with_suffix(".pdf")
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    text = markdown_path.read_text(encoding="utf-8")
    styles = build_styles(getSampleStyleSheet(), colors, ParagraphStyle, TA_RIGHT)

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=extract_title(text),
        author="Argo",
        subject="Report investigativo OSINT",
    )
    story = markdown_to_story(text, styles, Paragraph, Spacer)
    doc.build(story, onFirstPage=page_decorator, onLaterPages=page_decorator)
    return pdf_path


def build_styles(sample, colors, paragraph_style, align_right: int) -> dict:
    base = sample["BodyText"]
    return {
        "title": paragraph_style(
            "ArgoTitle",
            parent=base,
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#17384d"),
            spaceAfter=12,
        ),
        "h2": paragraph_style(
            "ArgoH2",
            parent=base,
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#65c7f7"),
            spaceBefore=12,
            spaceAfter=7,
        ),
        "h3": paragraph_style(
            "ArgoH3",
            parent=base,
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#8ccf9e"),
            spaceBefore=8,
            spaceAfter=5,
        ),
        "body": paragraph_style(
            "ArgoBody",
            parent=base,
            fontName="Helvetica",
            fontSize=9.3,
            leading=13.2,
            textColor=colors.HexColor("#1d2730"),
            spaceAfter=5,
        ),
        "bullet": paragraph_style(
            "ArgoBullet",
            parent=base,
            fontName="Helvetica",
            fontSize=8.8,
            leading=12.4,
            leftIndent=9,
            firstLineIndent=-6,
            textColor=colors.HexColor("#1d2730"),
            spaceAfter=4,
        ),
        "meta": paragraph_style(
            "ArgoMeta",
            parent=base,
            fontName="Helvetica",
            fontSize=7.5,
            leading=9,
            alignment=align_right,
            textColor=colors.HexColor("#607080"),
        ),
    }


def markdown_to_story(text: str, styles: dict, paragraph, spacer) -> list:
    story: list = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            story.append(spacer(1, 5))
            continue
        if line.startswith("# "):
            story.append(paragraph(escape_xml(clean_inline(line[2:])), styles["title"]))
        elif line.startswith("## "):
            story.append(paragraph(escape_xml(clean_inline(line[3:])), styles["h2"]))
        elif line.startswith("### "):
            story.append(paragraph(escape_xml(clean_inline(line[4:])), styles["h3"]))
        elif line.startswith("- "):
            story.append(paragraph("- " + escape_xml(clean_inline(line[2:])), styles["bullet"]))
        else:
            story.append(paragraph(escape_xml(clean_inline(line)), styles["body"]))
    return story


def clean_inline(value: str) -> str:
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
    value = value.replace("**", "").replace("`", "")
    value = value.replace("  ", " ")
    return value.strip()


def extract_title(markdown: str) -> str:
    for line in markdown.splitlines():
        if line.startswith("# "):
            return clean_inline(line[2:])[:160]
    return "Rapporto Argo"


def escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def page_decorator(canvas, doc) -> None:
    canvas.saveState()
    width, height = doc.pagesize
    canvas.setFillColorRGB(0.07, 0.09, 0.11)
    canvas.rect(0, height - 16, width, 16, fill=1, stroke=0)
    canvas.setFillColorRGB(0.39, 0.78, 0.97)
    canvas.rect(0, height - 16, width, 2, fill=1, stroke=0)
    canvas.setFillColorRGB(0.92, 0.96, 0.98)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(doc.leftMargin, height - 10.5, "Argo")
    canvas.setFillColorRGB(0.38, 0.44, 0.50)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(width - doc.rightMargin, 9, f"Pagina {doc.page}")
    canvas.restoreState()
