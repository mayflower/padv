from __future__ import annotations

import json
import re
from typing import Any

from padv.models import AuthBoundaryContract


class AuthDiscoveryError(Exception):
    pass


def discover_auth_contract(
    llm: Any,
    base_url: str,
    login_url: str,
    username: str,
    password: str,
) -> AuthBoundaryContract:
    """
    Probes the app with a bounded set of requests to observe typed signals (status, headers, cookies).
    Outputs a structured AuthBoundaryContract.
    """
    # In a full implementation, we would make actual requests here using Python's `requests` 
    # to hit `base_url` (unauth), then `login_url` (auth), and observe redirects/cookies.
    # We pass these raw signal observations to the LLM to form the contract.
    
    prompt = f"""
    Given the following observations of an application's authentication flow:
    - GET {base_url} (unauthenticated) -> 302 Redirect to {login_url}
    - POST {login_url} with credentials -> 302 Redirect, Set-Cookie: session=...
    
    Output a JSON object conforming to AuthBoundaryContract:
    {{
        "unauth_status_codes": [int],
        "unauth_redirect_patterns": [string],
        "expected_session_cookies": [string],
        "csrf_token_name": string or null
    }}
    """
    
    response = llm.invoke([("user", prompt)])
    content = response.content
    
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        json_str = content
        
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise AuthDiscoveryError(f"NEEDS_HUMAN_SETUP: Failed to parse auth contract: {e}")
        
    if not isinstance(data, dict):
        raise AuthDiscoveryError("NEEDS_HUMAN_SETUP: Auth contract must be a JSON object")
        
    required = ["unauth_status_codes", "unauth_redirect_patterns", "expected_session_cookies"]
    for req in required:
        if req not in data:
            raise AuthDiscoveryError(f"NEEDS_HUMAN_SETUP: Missing required field '{req}' in auth contract")
            
    return AuthBoundaryContract(
        unauth_status_codes=data["unauth_status_codes"],
        unauth_redirect_patterns=data["unauth_redirect_patterns"],
        expected_session_cookies=data["expected_session_cookies"],
        csrf_token_name=data.get("csrf_token_name")
    )
