"""The SDK only talks over verified TLS.

Everything the SDK sends carries the publishable key and, most of the time,
the user's credentials or tokens. This check fails when the library turns
certificate or host verification off, or carries a plain http:// address
(localhost aside, for development).
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "insecure-transport"

DISABLED_VERIFICATION = re.compile(
    r"rejectUnauthorized\s*:\s*false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED"
    r"|verify\s*=\s*False"
    r"|check_hostname\s*=\s*False"
    r"|_create_unverified_context"
    r"|CERT_NONE"
    r"|InsecureSkipVerify\s*:\s*true"
    r"|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)\s*(?:false|0)"
    r"|['\"]verify_peer(?:_name)?['\"]\s*=>\s*false"
    r"|VERIFY_NONE"
    r"|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|X509TrustManager|TrustAllCerts"
    r"|[aA]llowsArbitraryLoads"
    r"|badCertificateCallback"
    r"|usesCleartextTraffic"
    r"|disableEvaluation|serverTrustPolicy"
)

PLAIN_HTTP = re.compile(
    r"http://(?!localhost\b|127\.0\.0\.1|\[::1\]|www\.w3\.org/|schemas\.android\.com/|maven\.apache\.org/|"
    r"www\.apache\.org/|json-schema\.org/|[\"'`$<{\s]|$)"
)


def main() -> None:
    results: dict[Path, list[str]] = {}
    checked = sdk.source_files()
    for path in checked:
        text = sdk.read(path)
        if sdk.is_generated(text):
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if sdk.allowed(lines, index, CHECK):
                continue
            match = DISABLED_VERIFICATION.search(line)
            if match and not sdk.is_comment(line):
                results.setdefault(path, []).append(f"Line {index + 1}: `{match.group(0)}` turns TLS verification off")
            if PLAIN_HTTP.search(line) and not sdk.is_comment(line):
                results.setdefault(path, []).append(f"Line {index + 1}: plain http:// address in the library")
    sdk.report("INSECURE TRANSPORT", results, checked)


if __name__ == "__main__":
    main()
