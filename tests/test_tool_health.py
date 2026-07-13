"""Tests for tool health check in external_tools.py."""
from __future__ import annotations

from unittest.mock import patch

from osint_bot.external_tools import (
    TOOL_SPECS,
    all_tools_health,
    clear_health_cache,
    tool_health_status,
)


class TestToolHealthStatus:
    def setup_method(self):
        clear_health_cache()

    def teardown_method(self):
        clear_health_cache()

    def test_unknown_tool_returns_unavailable(self):
        result = tool_health_status("nonexistent_tool_xyz")
        assert result["name"] == "nonexistent_tool_xyz"
        assert result["available"] is False
        assert result["path"] is None
        assert "non registrato" in result["reason"]

    def test_response_structure(self):
        # Pick any registered tool
        name = next(iter(TOOL_SPECS))
        result = tool_health_status(name)
        assert "name" in result
        assert "available" in result
        assert "path" in result
        assert "reason" in result
        assert "checked_at" in result
        assert isinstance(result["available"], bool)

    def test_health_uses_cache(self):
        """Second call within TTL must return cached result without re-resolving."""
        name = next(iter(TOOL_SPECS))
        with patch("osint_bot.external_tools.resolve_command") as mock_resolve:
            mock_resolve.return_value = None
            tool_health_status(name)
            tool_health_status(name)
            tool_health_status(name)
            assert mock_resolve.call_count == 1, "cache miss — resolve called twice"

    def test_clear_cache_forces_refresh(self):
        name = next(iter(TOOL_SPECS))
        with patch("osint_bot.external_tools.resolve_command") as mock_resolve:
            mock_resolve.return_value = None
            tool_health_status(name)
            clear_health_cache()
            tool_health_status(name)
            assert mock_resolve.call_count == 2

    def test_unavailable_when_resolve_returns_none(self):
        name = next(iter(TOOL_SPECS))
        with patch("osint_bot.external_tools.resolve_command", return_value=None):
            result = tool_health_status(name)
            assert result["available"] is False
            assert "PATH" in result["reason"] or "env var" in result["reason"]

    def test_checked_at_is_iso_utc(self):
        name = next(iter(TOOL_SPECS))
        result = tool_health_status(name)
        ts = result["checked_at"]
        # Format YYYY-MM-DDTHH:MM:SSZ
        assert ts.endswith("Z")
        assert "T" in ts
        assert len(ts) == 20


class TestAllToolsHealth:
    def setup_method(self):
        clear_health_cache()

    def test_returns_one_entry_per_tool(self):
        results = all_tools_health()
        assert len(results) == len(TOOL_SPECS)
        names = {r["name"] for r in results}
        assert names == set(TOOL_SPECS.keys())

    def test_each_entry_has_required_keys(self):
        results = all_tools_health()
        for r in results:
            assert set(r.keys()) == {"name", "available", "path", "reason", "checked_at"}

    def test_sorted_alphabetically(self):
        results = all_tools_health()
        names = [r["name"] for r in results]
        assert names == sorted(names)
