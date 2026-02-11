"""BOTCHA speed challenge solver implementation."""

import hashlib


def solve_botcha(problems: list[int]) -> list[str]:
    """
    Solve BOTCHA speed challenge problems.

    For each problem number, compute SHA256 hash and return first 8 hex characters.

    Args:
        problems: List of 6-digit integers to solve

    Returns:
        List of 8-character hex strings (SHA256 hash prefixes)

    Example:
        >>> solve_botcha([123456])
        ['8d969eef']
    """
    solutions = []
    for num in problems:
        # Convert number to string, compute SHA256 hash
        hash_obj = hashlib.sha256(str(num).encode())
        hash_hex = hash_obj.hexdigest()
        # Return first 8 characters
        solutions.append(hash_hex[:8])
    return solutions
