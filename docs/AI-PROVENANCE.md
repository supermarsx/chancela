# AI provenance and human verification

This is the first provenance slice for AI-adjacent drafting surfaces.

## MCP draft outputs

`draft_act` and `draft_minutes` are MCP write-controlled tools that call `POST /acts` under the
configured integration API base path, normally `/api/v1`. They do not produce sealed minutes or
legal text. On success, the MCP server wraps the API act view in an `ai_draft` envelope with:

- `non_authoritative: true`
- `human_verification_required: true`
- `verification.status: "pending"`
- `verification.accepted_as_legal_text: false`
- `provenance.source.surface: "mcp"`
- `provenance.source.tool`
- `provenance.source.endpoint`
- `provenance.model: null`
- `provenance.provider: null`
- `provenance.created_at` as RFC 3339 UTC
- `provenance.actor`

The nested `draft` object must still be an unsealed API draft: `state == "Draft"` and
`ata_number`, `payload_digest`, and `seal_event_seq` are null. If the draft endpoint ever returns a
sealed/non-draft shape to these MCP tools, the MCP server returns a tool error instead of presenting
that payload as an AI draft.

## Legal effect

AI/MCP draft metadata is advisory provenance only. Legal effect still requires the normal human
workflow: review/edit the draft, satisfy compliance checks, advance through lifecycle states, and
seal through the existing API gates. The tenant AI/MCP gate remains default-off; with
`CHANCELA_AI_ENABLED` unset or false, the MCP server is not served.
