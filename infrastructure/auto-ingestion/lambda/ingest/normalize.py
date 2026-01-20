from typing import Any, Dict, List, Optional, Tuple


def deep_get(d: Dict[str, Any], path: List[str], default=None):
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def parse_assumed_role_arn(user_arn: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    # arn:aws:sts::<acct>:assumed-role/<roleName>/<sessionName>
    if not user_arn or ":assumed-role/" not in user_arn:
        return None, None
    try:
        after = user_arn.split(":assumed-role/")[1]
        parts = after.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return None, None


def mask_access_key(access_key_id: Optional[str], keep_last: int = 4) -> Optional[str]:
    if not access_key_id:
        return None
    if len(access_key_id) <= keep_last:
        return "*" * len(access_key_id)
    return "*" * (len(access_key_id) - keep_last) + access_key_id[-keep_last:]


def normalize_record(
    record: Dict[str, Any],
    *,
    mask_keys: bool = True,
    keep_heavy_fields: bool = False
) -> Dict[str, Any]:
    user_identity = record.get("userIdentity", {}) or {}
    user_arn = user_identity.get("arn")
    role_name, session_name = parse_assumed_role_arn(user_arn)

    access_key = user_identity.get("accessKeyId")
    if mask_keys:
        access_key = mask_access_key(access_key)

    raw_user_name = user_identity.get("userName")

    # mfaAuthenticated often shows as "true"/"false"
    mfa_raw = deep_get(user_identity, ["sessionContext", "attributes", "mfaAuthenticated"])
    if isinstance(mfa_raw, str):
        mfa_authenticated = (mfa_raw.lower() == "true")
    else:
        mfa_authenticated = bool(mfa_raw) if mfa_raw is not None else None

    principal_id = user_identity.get("principalId") or ""
    principal_suffix = principal_id.split(":")[-1] if ":" in principal_id else None

    actor = raw_user_name or session_name or principal_suffix or user_arn

    normalized = {
        # Identity
        "userType": user_identity.get("type"),
        "userArn": user_arn,
        "accountId": user_identity.get("accountId"),
        "principalId": principal_id or None,
        "accessKeyId": access_key,
        "sessionIssuerArn": deep_get(user_identity, ["sessionContext", "sessionIssuer", "arn"]),
        "roleName": role_name,
        "sessionName": session_name,
        "userName": raw_user_name,
        "actor": actor,
        "mfaAuthenticated": mfa_authenticated,

        # Core event
        "eventName": record.get("eventName"),
        "eventSource": record.get("eventSource"),
        "eventType": record.get("eventType"),
        "readOnly": record.get("readOnly"),
        "awsRegion": record.get("awsRegion"),
        "eventTime": record.get("eventTime"),
        "eventID": record.get("eventID"),
        "requestID": record.get("requestID"),

        # Network/client
        "sourceIPAddress": record.get("sourceIPAddress"),
        "userAgent": record.get("userAgent"),
        "vpcEndpointId": record.get("vpcEndpointId"),

        # Errors/context
        "errorCode": record.get("errorCode"),
        "errorMessage": record.get("errorMessage"),
        "additionalEventData": record.get("additionalEventData"),
        "tlsDetails": record.get("tlsDetails"),
    }

    # Heavy fields OFF by default
    if keep_heavy_fields:
        normalized["requestParameters"] = record.get("requestParameters")
        normalized["responseElements"] = record.get("responseElements")

    return normalized
