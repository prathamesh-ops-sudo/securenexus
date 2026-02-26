# Webhook and Outbound Integration Security

This document describes the security controls applied to all outbound webhook deliveries and integration callbacks in SecureNexus.

## URL Validation (SSRF Prevention)

Every webhook URL is validated at creation time, update time, and again at delivery time. The validator rejects:

- **Non-HTTP schemes**: Only `http:` and `https:` are allowed. `file:`, `ftp:`, `gopher:`, `data:`, and `javascript:` are blocked.
- **Loopback addresses**: `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- **Private IP ranges**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
- **Cloud metadata endpoints**: `169.254.169.254` (AWS/GCP metadata service), `fd00:ec2::254`
- **Internal Kubernetes hostnames**: `kubernetes.default`, `kubernetes.default.svc`, `metadata.google.internal`
- **Local TLDs**: `.local`, `.internal`, `.localhost`
- **IPv6 private ranges**: `fc00::/7` (unique local), `fe80::/10` (link-local)
- **Credentials in URL**: Usernames and passwords embedded in URLs are rejected

If a webhook URL fails validation, the delivery is logged as blocked and no outbound request is made.

## Outbound Request Policies

All outbound webhook deliveries use a hardened HTTP client with the following policies:

| Policy | Default | Description |
|--------|---------|-------------|
| Timeout | 10 seconds | Maximum time to wait for a response |
| Max response size | 64 KB | Response body is truncated beyond this limit |
| Redirect policy | Reject | HTTP redirects are rejected to prevent SSRF via redirect |
| HMAC signing | SHA-256 | Payloads are signed with `X-Webhook-Signature` and `X-Webhook-Timestamp` headers |

## Circuit Breaker

Each webhook has an independent circuit breaker that prevents repeated delivery attempts to failing endpoints:

- **Closed** (normal): Deliveries proceed normally
- **Open** (tripped): After 5 consecutive failures, the circuit opens and all deliveries are skipped for 60 seconds
- **Half-open** (recovery): After the cooldown period, one delivery attempt is allowed. If it succeeds, the circuit closes. If it fails, it reopens.

Circuit breaker status is visible in the webhook logs and via the `/api/outbound-webhooks/:id/test` endpoint.

## Per-Webhook Rate Limiting

Each webhook is rate-limited to 100 deliveries per 60-second window. Deliveries that exceed the rate limit are logged with a 429 status and skipped. The rate limit is applied per-webhook, not globally, so high-volume webhooks do not affect others.

## Delivery Logging and Redaction

Every webhook delivery attempt (successful or failed) is logged to the `outbound_webhook_logs` table with:

- Webhook ID, event type, timestamp
- HTTP status code and truncated response body
- Success/failure status

Sensitive data is redacted from logged payloads before storage:

- Fields containing `password`, `secret`, `token`, `apikey`, `authorization`, `credential`, or `private_key` are replaced with `[REDACTED]`
- Bearer tokens, API keys (`snx_*`, `ghp_*`), and AWS access key IDs (`AKIA*`) are redacted from string values

Delivery logs are accessible via `GET /api/outbound-webhooks/:id/logs` (most recent 50 entries).

## Webhook Signature Verification

Inbound webhooks are verified using HMAC-SHA256 with timing-safe comparison. The signature format is:

```
X-Webhook-Signature: sha256={hex_digest}
X-Webhook-Timestamp: {unix_timestamp_ms}
```

The signed payload is `{timestamp}.{body}`. Signatures older than 5 minutes are rejected to prevent replay attacks.
