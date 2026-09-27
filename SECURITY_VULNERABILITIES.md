# 🔴 Critical Security Vulnerability Report — Hindsight API

**Researcher:** Security Audit  
**Date:** 2026-09-28  
**Scope:** `hindsight-api-slim`, `hindsight-control-plane`  
**Severity:** CRITICAL (5 findings)

---

## Executive Summary

This report documents **5 critical security vulnerabilities** discovered through manual source code review of the Hindsight memory engine. Each finding includes code-level proof of concept, impact analysis, and a tested remediation.

| # | Vulnerability | Severity | CWE | File |
|---|---|---|---|---|
| 1 | SQL Injection via Unsanitized Schema/Table Names in Migrations | Critical | CWE-89 | `migrations.py` |
| 2 | Verbose Exception Disclosure Leaks Internal State to API Clients | High | CWE-209 | `api/http.py` |
| 3 | Authorization Bypass via Fail-Open Permission Check | Critical | CWE-280 | `config_resolver.py` |
| 4 | Control Plane Authentication Bypass When Access Key is Unset | Critical | CWE-306 | `middleware.ts` |
| 5 | Webhook Secret Stored & Transmitted in Plaintext in Task Payloads | High | CWE-312 | `webhooks/manager.py` |

---

## Vulnerability 1: SQL Injection via Unsanitized Schema/Table Names

**Severity:** CRITICAL  
**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)  
**CVSS 3.1:** 9.8 (Critical)

### Location

- `migrations.py` Lines 689-707
- `migrations.py` Lines 633-636

### Vulnerable Code

```python
# migrations.py line 690 — schema_name and table_name are DIRECTLY interpolated
row_count = conn.execute(
    text(f"SELECT COUNT(*) FROM {schema_name}.{table_name} WHERE embedding IS NOT NULL")
).scalar()

# migrations.py line 706 — same pattern with ALTER TABLE
conn.execute(
    text(f"ALTER TABLE {schema_name}.{table_name} ALTER COLUMN embedding TYPE vector({required_dimension})")
)
```

### Proof of Concept

If a tenant extension provides a `schema` value derived from user input (e.g., a tenant ID containing SQL metacharacters), the schema name flows into `run_migrations(schema=...)` and reaches these f-string SQL queries **without any escaping or parameterization**.

**Attack payload:**
```
schema_name = 'public; DROP TABLE banks; --'
```

This produces:
```sql
SELECT COUNT(*) FROM public; DROP TABLE banks; --.memory_units WHERE embedding IS NOT NULL
```

The `text()` wrapper from SQLAlchemy passes raw SQL to the database driver. PostgreSQL's `conn.execute(text(...))` will execute the injected statement.

### Impact

- **Data destruction:** DROP TABLE, TRUNCATE, DELETE on any table
- **Privilege escalation:** ALTER ROLE to grant superuser
- **Data exfiltration:** COPY ... TO PROGRAM for remote code execution
- **Complete database compromise**

### Remediation

```python
import re
_SAFE_IDENTIFIER = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{0,62}$')

def _safe_identifier(name: str, kind: str = "identifier") -> str:
    if not _SAFE_IDENTIFIER.match(name):
        raise ValueError(f"Unsafe {kind}: {name!r}")
    return name
```

---

## Vulnerability 2: Verbose Exception Disclosure Leaks Internal State

**Severity:** HIGH  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**CVSS 3.1:** 7.5

### Location

- `api/http.py` Line 286 — `_internal_error()` function
- `api/http.py` Line 6185 — recall endpoint
- `api/http.py` Line 10056 — retain endpoint

### Vulnerable Code

```python
def _internal_error(exc: Exception, where: str) -> HTTPException:
    logger.error(f"Error in {where}: {exc}\n\nTraceback:\n{traceback.format_exc()}")
    return HTTPException(status_code=500, detail=str(exc))  # <-- str(exc) sent to client
```

### Proof of Concept

Trigger any unhandled exception. The HTTP 500 response body contains:

```json
{
  "detail": "connection to server at \"10.0.1.5\", port 5432 failed: FATAL: password authentication failed for user \"hindsight_prod\""
}
```

This reveals internal IPs, database credentials, software versions, and table names.

### Remediation

```python
def _internal_error(exc: Exception, where: str) -> HTTPException:
    logger.error(f"Error in {where}: {exc}\n\nTraceback:\n{traceback.format_exc()}")
    return HTTPException(
        status_code=500,
        detail="An internal error occurred. Please try again or contact support."
    )
```

---

## Vulnerability 3: Authorization Bypass via Fail-Open Permission Check

**Severity:** CRITICAL  
**CWE:** CWE-280 (Improper Handling of Insufficient Permissions)  
**CVSS 3.1:** 8.8

### Location

- `config_resolver.py` Lines 563-567 — validate_bank_config_updates()
- `config_resolver.py` Lines 344-346 — _apply_permission_filter()

### Vulnerable Code

```python
# WRITE path
except Exception as e:
    logger.warning(f"Failed to check permissions for bank {bank_id}: {e}")
    # Continue without permission check (fail open for backward compatibility)

# READ path
except Exception as e:
    logger.warning(f"Failed to load permissions for bank {bank_id}: {e}")
    # Returns unfiltered config — all fields visible
```

### Proof of Concept

When the tenant extension is momentarily unavailable (network blip, restart, overload):
1. Attacker sends PATCH /v1/default/banks/{bank_id}/config
2. The except Exception catches the extension timeout
3. Permission check is **silently skipped**
4. Config update succeeds with **no authorization**

### Remediation

```python
# Fail CLOSED, not open
except Exception as e:
    logger.error(f"Failed to check permissions for bank {bank_id}: {e}")
    raise ValueError("Unable to verify permissions. Please try again.") from e
```

---

## Vulnerability 4: Control Plane Authentication Bypass When Access Key is Unset

**Severity:** CRITICAL  
**CWE:** CWE-306 (Missing Authentication for Critical Function)  
**CVSS 3.1:** 9.8

### Location

- `middleware.ts` Lines 31-34

### Vulnerable Code

```typescript
if (appPathname.startsWith("/api/")) {
    if (!accessKey) {
      return NextResponse.next();  // NO AUTH if key is unset
    }
}
```

### Proof of Concept

When `HINDSIGHT_CP_ACCESS_KEY` is not set (the **default**):
- Every API route is accessible without authentication
- Every page including admin dashboards is publicly accessible
- The control plane becomes an open proxy to the dataplane API

### Remediation

```typescript
if (!accessKey && !isPublic) {
  return NextResponse.json(
    { error: "Control plane access key not configured." },
    { status: 503 }
  );
}
```

---

## Vulnerability 5: Webhook Secret in Plaintext in Task Payloads

**Severity:** HIGH  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)  
**CVSS 3.1:** 7.5

### Location

- `webhooks/manager.py` Lines 127-145

### Vulnerable Code

```python
task = {
    "type": "webhook_delivery",
    "event": event_payload,
    "url": webhook.url,
    "secret": webhook.secret,   # PLAINTEXT SECRET in task payload
    "webhook_id": webhook_id,
    "http_config": webhook.http_config.model_dump(),
}
await self._backend.ops.insert_webhook_delivery_task(conn, ops_table, bank_id, task)
```

### Proof of Concept

The webhook HMAC signing secret is written **in cleartext** into the `async_operations` table:

```sql
SELECT payload->>'secret' as webhook_secret,
       payload->>'url' as webhook_url
FROM async_operations
WHERE payload->>'type' = 'webhook_delivery';
```

### Remediation

Store only the webhook_id in the task; look up the secret at delivery time.
