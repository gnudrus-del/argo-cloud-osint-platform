import unittest

from osint_bot.extract import extract_html, normalize_url


class ExtractTests(unittest.TestCase):
    def test_extracts_title_description_links_and_email(self):
        body = """
        <html>
          <head>
            <title>Example Page</title>
            <meta name="description" content="A public page">
            <script>hidden@example.com</script>
          </head>
          <body>
            Contact security@example.com
            <a href="/about#team">About</a>
          </body>
        </html>
        """
        title, description, text, links, emails = extract_html(body, "https://example.com/index.html")

        self.assertEqual(title, "Example Page")
        self.assertEqual(description, "A public page")
        self.assertIn("Contact security@example.com", text)
        self.assertEqual(links, ["https://example.com/about"])
        self.assertEqual(emails, ["security@example.com"])

    def test_normalize_rejects_non_http(self):
        self.assertEqual(normalize_url("mailto:test@example.com"), "")


if __name__ == "__main__":
    unittest.main()

