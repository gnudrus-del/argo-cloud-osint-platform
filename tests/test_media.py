import tempfile
import unittest
from pathlib import Path

from osint_bot.media import (
    _gps_to_decimal,
    analyze_media_file,
    build_reverse_search_urls,
    extract_gps_from_exif,
)

PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6360000002000100ffff03000006000557bfab0d0000000049454e44ae426082"
)


class MediaTests(unittest.TestCase):
    def test_png_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.png"
            path.write_bytes(PNG_1X1)
            metadata = analyze_media_file(path)

        self.assertEqual(metadata.media_type, "image/png")
        self.assertEqual(metadata.width, 1)
        self.assertEqual(metadata.height, 1)
        self.assertEqual(len(metadata.sha256), 64)


class ReverseSearchUrlsTests(unittest.TestCase):
    def test_all_engines_present(self):
        urls = build_reverse_search_urls("abc123", "test.jpg")
        for k in ("google_lens", "yandex_images", "tineye", "bing_visual", "note"):
            self.assertIn(k, urls)

    def test_engines_use_https(self):
        urls = build_reverse_search_urls("abc123", "test.jpg")
        for k in ("google_lens", "yandex_images", "tineye", "bing_visual"):
            self.assertTrue(urls[k].startswith("https://"), f"{k} not https")

    def test_note_contains_hash_preview(self):
        h = "a" * 64
        urls = build_reverse_search_urls(h, "x.jpg")
        self.assertIn("a" * 16, urls["note"])


class GPSConversionTests(unittest.TestCase):
    def test_decimal_north(self):
        coord = [[41, 1], [53, 1], [245, 10]]
        result = _gps_to_decimal(coord, "N")
        self.assertIsNotNone(result)
        self.assertGreater(result, 41.88)
        self.assertLess(result, 41.90)

    def test_decimal_south_is_negative(self):
        self.assertEqual(_gps_to_decimal([[33, 1], [0, 1], [0, 1]], "S"), -33.0)

    def test_decimal_west_is_negative(self):
        self.assertEqual(_gps_to_decimal([[10, 1], [0, 1], [0, 1]], "W"), -10.0)

    def test_invalid_coord_returns_none(self):
        self.assertIsNone(_gps_to_decimal("nope", "N"))
        self.assertIsNone(_gps_to_decimal([1, 2], "N"))
        self.assertIsNone(_gps_to_decimal([[0, 0], [0, 1], [0, 1]], "N"))

    def test_extract_gps_no_gpsinfo(self):
        self.assertIsNone(extract_gps_from_exif({}))
        self.assertIsNone(extract_gps_from_exif({"GPSInfo": "string"}))

    def test_extract_gps_full(self):
        exif = {
            "GPSInfo": {
                "GPSLatitude": [[45, 1], [0, 1], [0, 1]],
                "GPSLatitudeRef": "N",
                "GPSLongitude": [[9, 1], [0, 1], [0, 1]],
                "GPSLongitudeRef": "E",
                "GPSAltitude": [120, 1],
                "GPSDateStamp": "2026:06:27",
            }
        }
        gps = extract_gps_from_exif(exif)
        self.assertEqual(gps["lat"], 45.0)
        self.assertEqual(gps["lon"], 9.0)
        self.assertEqual(gps["altitude_m"], 120.0)
        self.assertEqual(gps["date"], "2026:06:27")


class MediaMetadataExtendedTests(unittest.TestCase):
    def test_to_dict_has_new_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.png"
            path.write_bytes(PNG_1X1)
            meta = analyze_media_file(path)
            d = meta.to_dict()
            self.assertIn("exif", d)
            self.assertIn("gps", d)
            self.assertIn("reverse_search", d)
            self.assertIn("mime", d)
            self.assertEqual(d["mime"], "image/png")


if __name__ == "__main__":
    unittest.main()

