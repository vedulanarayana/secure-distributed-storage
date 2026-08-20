from typing import Protocol

PERMISSION_RANK = {"read": 1, "write": 2, "owner": 3}


class PermissionSource(Protocol):
    def get_permission(self, user_id: str, file_id: str) -> str | None: ...


def has_permission(store: PermissionSource, user_id: str, file_id: str, required: str) -> bool:
    granted = store.get_permission(user_id, file_id)
    if granted is None:
        return False
    return PERMISSION_RANK.get(granted, 0) >= PERMISSION_RANK.get(required, 999)
