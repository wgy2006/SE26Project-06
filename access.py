from typing import Any, Mapping


DEFAULT_POLICIES = {
    "admin": {"*"},
    "editor": {"read", "write"},
    "viewer": {"read"},
}


def check_access(
    payload: Mapping[str, Any],
    policies: Mapping[str, set[str]] | None = None,
) -> dict[str, Any]:
    """
    Check whether a user can perform an action on a resource.

    Expected payload:
        {
            "user_id": "u001",
            "role": "editor",
            "action": "write",
            "resource": "document:42"
        }
    """
    rules = policies or DEFAULT_POLICIES
    required_fields = ("user_id", "role", "action", "resource")

    missing = [field for field in required_fields if not payload.get(field)]
    if missing:
        return {
            "ok": False,
            "allowed": False,
            "code": "BAD_REQUEST",
            "message": f"Missing required field(s): {', '.join(missing)}",
        }

    user_id = str(payload["user_id"])
    role = str(payload["role"]).lower()
    action = str(payload["action"]).lower()
    resource = str(payload["resource"])

    if role not in rules:
        return {
            "ok": False,
            "allowed": False,
            "code": "INVALID_ROLE",
            "message": f"Role must be one of: {', '.join(sorted(rules))}",
        }

    allowed_actions = rules[role]
    allowed = "*" in allowed_actions or action in allowed_actions

    return {
        "ok": True,
        "allowed": allowed,
        "code": "ACCESS_GRANTED" if allowed else "ACCESS_DENIED",
        "message": (
            f"User {user_id} can {action} {resource}."
            if allowed
            else f"User {user_id} cannot {action} {resource}."
        ),
        "data": {
            "user_id": user_id,
            "role": role,
            "action": action,
            "resource": resource,
        },
    }


if __name__ == "__main__":
    request_data = {
        "user_id": "u001",
        "role": "editor",
        "action": "write",
        "resource": "document:42",
    }
    print(check_access(request_data))
