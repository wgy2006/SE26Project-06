def access(role: str, action: str) -> bool:
    """
    Check whether a role is allowed to perform an action.

    Rules:
        admin: all actions
        editor: read, write
        viewer: read
    """
    if not role or not action:
        return False

    permissions = {
        "admin": {"*"},
        "editor": {"read", "write"},
        "viewer": {"read"},
    }

    role = role.lower().strip()
    action = action.lower().strip()

    if role not in permissions:
        return False

    allowed_actions = permissions[role]
    return "*" in allowed_actions or action in allowed_actions


if __name__ == "__main__":
    print(access("admin", "delete"))
    print(access("editor", "write"))
    print(access("viewer", "write"))
