# Optional read-only Google integrations

The default sandbox does not contact Gmail or Postmaster. Its capture receiver never delivers mail externally. These adapters run only when explicitly called and when the operator supplies OAuth access tokens for accounts/domains they are authorized to inspect.

Supply `GHOST_GMAIL_ACCESS_TOKEN` with Gmail read-only access and/or `GHOST_POSTMASTER_ACCESS_TOKEN` with Postmaster read-only traffic access. Use environment variables or an ignored `.env`; never commit tokens. The access-token lifecycle belongs to your OAuth client or secret manager. Interactive consent and automatic refresh are not implemented. Expired tokens produce explicit unavailable responses with Google's HTTP status, without echoing credentials.

```sh
docker compose -f compose.yaml -f compose.spam.yaml -f compose.google.yaml up -d --build
```

`POST /v1/integrations/gmail/import` accepts:

```json
{"gmail_message_id":"YOUR_GMAIL_MESSAGE_ID","run_id":"campaign-2026-10-a","audit":true}
```

It fetches the message's raw MIME and current labels, captures it locally, optionally audits it, and records a Gmail outcome only when `SPAM` or `INBOX` is actually present. An archived/Sent message is not automatically labeled inbox. `audit:true` saves a report before feedback for later calibration export. This reads the owned mailbox; it does not send, label, move, or delete Gmail messages. Do not poll arbitrary accounts.

`GET /v1/integrations/postmaster/example.com/compliance` retrieves the v2 compliance response. `POST /v1/integrations/postmaster/example.com/stats` forwards a bounded v2 domain-statistics query containing `metricDefinitions`, `timeQuery`, optional `pageSize` (1–200), `pageToken`, and `aggregationGranularity` (`DAILY` or `OVERALL`). The nested Google metric/time schemas are preserved rather than reinterpreted; use the official reference below to select valid fields. Inspect the returned `data` and any pagination token explicitly.

Responses preserve Google's JSON, source URL, and observation time. Access denied, insufficient traffic, absent data, and network failures are not replaced with guessed reputation. Postmaster telemetry does not automatically become a Gmail placement percentage. Fit the separate optional calibration workflow with authorized outcomes and measured features if needed.

Sources:

- [Gmail message retrieval](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
- [Postmaster v2 compliance](https://developers.google.com/workspace/gmail/postmaster/reference/rest/v2/domains/getComplianceStatus)
- [Postmaster v2 domain statistics](https://developers.google.com/workspace/gmail/postmaster/reference/rest/v2/domains.domainStats/query)
