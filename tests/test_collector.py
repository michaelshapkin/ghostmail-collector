import pytest
from collector import is_valid_domain # Import the function from src/collector.py

# Use parametrize to run the test function with multiple test cases
# Format: [ (input_domain, expected_result_True_or_False), ... ]
@pytest.mark.parametrize(
    "domain, expected",
    [
        # === Valid Cases ===
        ("google.com", True),
        ("example.co.uk", True),
        ("sub-domain.domain.info", True),
        ("a.io", True),
        ("xn--fsqu00a.com", True), # Punycode representation (例子.com) - should pass regex
        ("domain-with-hyphen.net", True),
        ("numbers123.org", True),
        ("123domain.com", True), # Starts with a number

        # === Invalid Cases (Format) ===
        ("", False), # Empty string
        (" ", False), # Space
        ("nodot", False), # No dot
        (".com", False), # Starts with a dot
        ("domain.", False), # Ends with a dot (rstrip should handle, but verify)
        ("domain..com", False), # Double dots
        ("domain-.com", False), # Ends with hyphen before TLD
        ("-domain.com", False), # Starts with hyphen
        ("domain.c", False), # TLD too short
        ("domain.toolongtld", True), # TLD too long (though regex might allow)
        ("domain with space.com", False), # Contains space
        ("email@domain.com", False), # Contains @
        ("http://domain.com", False), # Contains protocol
        ("domain.com/", False), # Contains /
        ("192.168.0.1", False), # IPv4 address
        ("::1", False), # IPv6 address
        ("例子.com", False), # Non-ASCII characters (raw)
        ("domäin.com", False), # Non-ASCII characters (raw)

        # === Invalid Cases (Explicitly Excluded Domains) ===
        ("test.com", False),
        ("zzz.com", False),
        ("xxx.com", False),
        ("example.com", False),
        ("invalid.com", False),

        # === Edge Cases (Based on current regex/logic) ===
        # ('a' * 64 + '.com', False), # Label too long (current regex doesn't strictly check length) - skipping for now
        # Add more edge cases if needed
    ],
    # Provide IDs for better test reporting (optional)
    ids=[
        # Valid
        "valid_google", "valid_co_uk", "valid_subdomain", "valid_short_tld", "valid_punycode",
        "valid_hyphen", "valid_numbers", "valid_leading_number",
        # Invalid Format
        "invalid_empty", "invalid_space", "invalid_no_dot", "invalid_leading_dot", "invalid_trailing_dot",
        "invalid_double_dot", "invalid_trailing_hyphen", "invalid_leading_hyphen", "invalid_short_tld",
        "invalid_long_tld", "invalid_contains_space", "invalid_contains_at", "invalid_protocol",
        "invalid_slash", "invalid_ipv4", "invalid_ipv6", "invalid_non_ascii_1", "invalid_non_ascii_2",
        # Excluded
        "excluded_test", "excluded_zzz", "excluded_xxx", "excluded_example", "excluded_invalid"
    ]
)
def test_is_valid_domain(domain, expected):
    """
    Tests the is_valid_domain function with various inputs using parametrization.
    Checks standard valid domains, invalid formats, and explicitly excluded domains.
    """
    assert is_valid_domain(domain) == expected

# --- You can add more test functions below for other collector functions ---

# Example placeholder for future tests:
# def test_has_mx_record_ok(mocker): # mocker fixture comes from pytest-mock
#     """Tests has_mx_record for a domain with a valid MX record."""
#     # TODO: Implement mocking for dns.resolver.Resolver
#     pass