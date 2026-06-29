import tempfile
import unittest
from pathlib import Path

from osint_bot.pdf_report import write_pdf_from_markdown


class PdfReportTests(unittest.TestCase):
    def test_write_pdf_from_markdown_creates_readable_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            markdown_path = Path(tmp) / "report.md"
            markdown_path.write_text(
                "# Rapporto investigativo OSINT - example.com\n\n"
                "## Sintesi discorsiva\n\n"
                "La ricerca ha prodotto evidenze verificabili.\n\n"
                "- Fonte pubblica confermata.\n",
                encoding="utf-8",
            )

            pdf_path = write_pdf_from_markdown(markdown_path)

            self.assertTrue(pdf_path.is_file())
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
