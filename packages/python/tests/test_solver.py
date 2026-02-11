"""Tests for BOTCHA solver implementation."""

import re
from botcha.solver import solve_botcha


def test_solve_botcha_known_values():
    """Test solver with known SHA256 hash values."""
    # Test vector: 123456 -> sha256 -> first 8 chars
    result = solve_botcha([123456])
    assert result == ["8d969eef"]

    # Test vector: 999999
    result = solve_botcha([999999])
    assert result == ["937377f0"]

    # Test vector: 100000
    result = solve_botcha([100000])
    assert result == ["3bb78535"]


def test_solve_botcha_multiple_problems():
    """Test solver with multiple problems at once."""
    problems = [123456, 999999, 100000]
    expected = ["8d969eef", "937377f0", "3bb78535"]
    result = solve_botcha(problems)
    assert result == expected


def test_solve_botcha_empty_list():
    """Test solver with empty input returns empty output."""
    result = solve_botcha([])
    assert result == []


def test_solve_botcha_single_element():
    """Test solver with single element."""
    result = solve_botcha([555555])
    assert result == ["af41e68e"]
    assert len(result) == 1


def test_solve_botcha_preserves_order():
    """Test that solver preserves input order."""
    problems = [111111, 555555, 100000]
    expected = ["bcb15f82", "af41e68e", "3bb78535"]
    result = solve_botcha(problems)
    assert result == expected


def test_solve_botcha_result_format():
    """Test that all results are 8-character hex strings."""
    problems = [123456, 999999, 100000, 555555, 111111]
    results = solve_botcha(problems)

    # Check all results are 8 chars
    assert all(len(r) == 8 for r in results)

    # Check all results are valid hex (lowercase)
    hex_pattern = re.compile(r"^[0-9a-f]{8}$")
    assert all(hex_pattern.match(r) for r in results)


def test_solve_botcha_deterministic():
    """Test that solver produces consistent results."""
    problems = [123456, 999999]
    result1 = solve_botcha(problems)
    result2 = solve_botcha(problems)
    assert result1 == result2


def test_solve_botcha_different_inputs():
    """Test that different inputs produce different outputs."""
    result1 = solve_botcha([123456])
    result2 = solve_botcha([123457])
    assert result1 != result2
