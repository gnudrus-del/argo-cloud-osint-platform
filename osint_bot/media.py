from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MediaMetadata:
    path: str
    filename: str
    size_bytes: int
    sha256: str
    media_type: str
    width: int | None = None
    height: int | None = None
    notes: list[str] | None = None
    exif: dict | None = None
    gps: dict | None = None  # {lat, lon, altitude?, timestamp?}
    reverse_search: dict | None = None  # {google_lens, yandex, tineye, bing}
    mime: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "media_type": self.media_type,
            "mime": self.mime or self.media_type,
            "width": self.width,
            "height": self.height,
            "notes": self.notes or [],
            "exif": self.exif or {},
            "gps": self.gps or {},
            "reverse_search": self.reverse_search or {},
        }


def analyze_media_file(path: str | Path) -> MediaMetadata:
    file_path = Path(path)
    data = file_path.read_bytes()
    media_type = detect_media_type(file_path, data)
    width, height = image_dimensions(data, media_type)
    notes: list[str] = []

    exif_data: dict | None = None
    gps_data: dict | None = None
    if media_type == "image/jpeg":
        exif_data = extract_jpeg_exif(data)
        if exif_data:
            gps_data = extract_gps_from_exif(exif_data)
            if gps_data:
                notes.append(f"GPS estratto: lat={gps_data.get('lat')}, lon={gps_data.get('lon')}")
        else:
            notes.append("Nessun EXIF rilevato nel JPEG.")

    if width is None and media_type.startswith("image/"):
        notes.append("Formato immagine riconosciuto ma dimensioni non estratte dal parser minimale.")
    if media_type.startswith("video/"):
        notes.append("Per durata, codec e stream usare il wrapper ffprobe se installato.")

    sha256 = hashlib.sha256(data).hexdigest()
    reverse_search = build_reverse_search_urls(sha256, file_path.name)

    return MediaMetadata(
        path=str(file_path),
        filename=file_path.name,
        size_bytes=os.path.getsize(file_path),
        sha256=sha256,
        media_type=media_type,
        mime=media_type,
        width=width,
        height=height,
        notes=notes,
        exif=exif_data,
        gps=gps_data,
        reverse_search=reverse_search,
    )


# ---------------------------------------------------------------------------
# Reverse image search URL builder (no actual upload — prefilled queries)
# ---------------------------------------------------------------------------
def build_reverse_search_urls(sha256: str, filename: str) -> dict:
    """Build URLs for manual reverse-image search engines.

    These are not auto-executed (we don't upload user images to third-party
    services). They are prefilled forms / search pages the user can click.
    """
    return {
        "google_lens": "https://lens.google.com/uploadbyurl",
        "yandex_images": "https://yandex.com/images/search?source=collections&rpt=imageview",
        "tineye": "https://tineye.com/",
        "bing_visual": "https://www.bing.com/visualsearch",
        "note": (
            "Carica manualmente il file su questi servizi per il reverse image search. "
            f"Hash di riferimento per identificarlo: {sha256[:16]}…"
        ),
    }


# ---------------------------------------------------------------------------
# EXIF parser — pure Python, no Pillow dependency
# ---------------------------------------------------------------------------
def extract_jpeg_exif(data: bytes) -> dict | None:
    """Parse EXIF (TIFF inside APP1 marker) from a JPEG byte stream.

    Returns a dict mapping tag_id -> {tag_name, value} for known tags,
    plus a special "GPSInfo" key with the GPS sub-IFD when present.
    Returns None if no EXIF block is found.
    """
    # Find APP1 marker (0xFFE1)
    idx = 2
    while idx + 4 < len(data):
        if data[idx] != 0xFF:
            idx += 1
            continue
        marker = data[idx + 1]
        if marker == 0xE1:  # APP1
            seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
            seg = data[idx + 4 : idx + 2 + seg_len]
            if seg.startswith(b"Exif\x00\x00"):
                return _parse_tiff(seg[6:])
            idx += 2 + seg_len
            continue
        if marker in (0xD8, 0xD9, 0x01):
            idx += 2
            continue
        if idx + 4 > len(data):
            break
        seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
        idx += 2 + seg_len
    return None


# EXIF tag names (subset of the most useful ones)
_EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8825: "GPSInfoIFDPointer",
    0x8769: "ExifIFDPointer",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9286: "UserComment",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISOSpeedRatings",
    0xA433: "LensMake",
    0xA434: "LensModel",
}

_GPS_TAGS = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x001D: "GPSDateStamp",
    0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection",
}


def _parse_tiff(tiff: bytes) -> dict:
    """Parse a TIFF block and return a dict of EXIF tags."""
    if len(tiff) < 8:
        return {}
    byte_order = tiff[:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        return {}
    magic = struct.unpack(endian + "H", tiff[2:4])[0]
    if magic != 0x002A:
        return {}
    ifd0_off = struct.unpack(endian + "I", tiff[4:8])[0]
    result = _read_ifd(tiff, ifd0_off, endian, _EXIF_TAGS)
    # Follow ExifIFD pointer
    if "ExifIFDPointer" in result:
        exif_ifd = result["ExifIFDPointer"]
        if isinstance(exif_ifd, int):
            sub = _read_ifd(tiff, exif_ifd, endian, _EXIF_TAGS)
            result.update({k: v for k, v in sub.items() if k != "ExifIFDPointer"})
    # Follow GPSInfo pointer
    if "GPSInfoIFDPointer" in result:
        gps_off = result["GPSInfoIFDPointer"]
        if isinstance(gps_off, int):
            gps = _read_ifd(tiff, gps_off, endian, _GPS_TAGS)
            result["GPSInfo"] = gps
    return result


def _read_ifd(tiff: bytes, offset: int, endian: str, tag_table: dict) -> dict:
    """Read a single IFD at the given offset."""
    if offset + 2 > len(tiff):
        return {}
    try:
        num_entries = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
    except struct.error:
        return {}
    entries: dict = {}
    pos = offset + 2
    for _ in range(num_entries):
        if pos + 12 > len(tiff):
            break
        try:
            tag = struct.unpack(endian + "H", tiff[pos : pos + 2])[0]
            ftype = struct.unpack(endian + "H", tiff[pos + 2 : pos + 4])[0]
            count = struct.unpack(endian + "I", tiff[pos + 4 : pos + 8])[0]
        except struct.error:
            break
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 10: 8}
        size = type_sizes.get(ftype, 0) * count
        if size <= 4:
            val_bytes = tiff[pos + 8 : pos + 12]
        else:
            val_off = struct.unpack(endian + "I", tiff[pos + 8 : pos + 12])[0]
            val_bytes = tiff[val_off : val_off + size]
        value = _parse_value(val_bytes, ftype, count, endian)
        name = tag_table.get(tag, f"Tag_0x{tag:04X}")
        entries[name] = value
        pos += 12
    return entries


def _parse_value(raw: bytes, ftype: int, count: int, endian: str):
    """Parse a single EXIF value based on its type."""
    try:
        if ftype == 1:  # BYTE
            return list(raw[:count])
        if ftype == 2:  # ASCII
            return raw[:count].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        if ftype == 3:  # SHORT
            return list(struct.unpack(endian + f"{count}H", raw[: 2 * count])) \
                if count > 1 else struct.unpack(endian + "H", raw[:2])[0]
        if ftype == 4:  # LONG
            return list(struct.unpack(endian + f"{count}I", raw[: 4 * count])) \
                if count > 1 else struct.unpack(endian + "I", raw[:4])[0]
        if ftype == 5:  # RATIONAL
            vals = []
            for i in range(count):
                num, den = struct.unpack(endian + "II", raw[i * 8 : i * 8 + 8])
                vals.append([num, den])
            return vals[0] if count == 1 else vals
        if ftype == 10:  # SRATIONAL
            vals = []
            for i in range(count):
                num, den = struct.unpack(endian + "ii", raw[i * 8 : i * 8 + 8])
                vals.append([num, den])
            return vals[0] if count == 1 else vals
        if ftype == 7:  # UNDEFINED
            return raw[:count].hex()
    except struct.error:
        return None
    return None


def extract_gps_from_exif(exif: dict) -> dict | None:
    """Convert GPSInfo IFD into decimal lat/lon."""
    gps = exif.get("GPSInfo")
    if not isinstance(gps, dict):
        return None
    lat = _gps_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
    lon = _gps_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    if lat is None or lon is None:
        return None
    result = {"lat": lat, "lon": lon}
    alt = gps.get("GPSAltitude")
    if isinstance(alt, list) and len(alt) == 2 and alt[1]:
        result["altitude_m"] = alt[0] / alt[1]
    if "GPSDateStamp" in gps:
        result["date"] = gps["GPSDateStamp"]
    return result


def _gps_to_decimal(coord, ref) -> float | None:
    """Convert (deg, min, sec) rational triplet + ref char ('N'/'S'/'E'/'W') to decimal."""
    if not isinstance(coord, list) or len(coord) != 3:
        return None
    try:
        parts = []
        for c in coord:
            if isinstance(c, list) and len(c) == 2 and c[1]:
                parts.append(c[0] / c[1])
            else:
                return None
        decimal = parts[0] + parts[1] / 60 + parts[2] / 3600
        if isinstance(ref, str) and ref.upper() in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except (ZeroDivisionError, TypeError):
        return None


def detect_media_type(path: Path, data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "video/mp4"
    suffix = path.suffix.lower().lstrip(".")
    if suffix in {"jpg", "jpeg", "png", "gif", "webp"}:
        return f"image/{'jpeg' if suffix == 'jpg' else suffix}"
    if suffix in {"mov", "mp4", "m4v", "avi", "mkv", "webm"}:
        return f"video/{suffix}"
    return "application/octet-stream"


def image_dimensions(data: bytes, media_type: str) -> tuple[int | None, int | None]:
    if media_type == "image/png" and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
        return width, height
    if media_type == "image/gif" and len(data) >= 10:
        width, height = struct.unpack("<HH", data[6:10])
        return width, height
    if media_type == "image/jpeg":
        return jpeg_dimensions(data)
    return None, None


def jpeg_dimensions(data: bytes) -> tuple[int | None, int | None]:
    index = 2
    while index + 9 < len(data):
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        index += 2
        if marker in {0xD8, 0xD9}:
            continue
        if index + 2 > len(data):
            break
        segment_length = struct.unpack(">H", data[index : index + 2])[0]
        if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            if index + 7 <= len(data):
                height, width = struct.unpack(">HH", data[index + 3 : index + 7])
                return width, height
        index += segment_length
    return None, None
