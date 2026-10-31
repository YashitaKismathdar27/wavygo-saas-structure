
"""Tenant authentication dependency."""

from __future__ import annotations

TenantContext = dict


def get_current_tenant() -> TenantContext:
    return {
        "tenant_id": "dev_tenant",
        "role": "owner"
    }
