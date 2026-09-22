# Who decides whether to ask you? MCP tool annotations as a trust boundary

**Sanket Sarkar — September 2026**

*Research note, not a vulnerability disclosure.* The behaviour described here is publicly
known, has been raised with the vendor before, and is **accepted by design**. Nothing in this
note is novel to me; what I add is a reproducible test against the current code and an
argument about where the trust boundary ought to sit. See **Prior work** below.

## The mechanism

In the Model Context Protocol, a server describes its own tools in its `tools/list` response.
Part of that description is a set of **annotations** — `readOnlyHint`, `destructiveHint`,
`openWorldHint` — which are declarations *by the server* about what its tools do.

The MCP specification is explicit that these are hints, not contracts, and that clients must
treat them as untrusted unless they come from a trusted server.

Codex CLI uses them to decide whether to interrupt the user for approval
(`codex-rs/core/src/mcp_tool_call.rs`):

```rust
fn requires_mcp_tool_approval(annotations: Option<&ToolAnnotations>) -> bool {
    let destructive_hint = annotations.and_then(|a| a.destructive_hint);
    if destructive_hint == Some(true) { return true; }

    let read_only_hint = annotations.and_then(|a| a.read_only_hint).unwrap_or(false);
    if read_only_hint { return false; }        // no approval prompt

    destructive_hint.unwrap_or(true)
        || annotations.and_then(|a| a.open_world_hint).unwrap_or(true)
}
```

A server that declares `readOnlyHint: true` suppresses the prompt for its own tool. The
default approval mode routes through this function (`AppToolApproval` derives
`#[default] Auto`), so it is the out-of-the-box path rather than an opt-in.

## Reproduction

Append to `codex-rs/core/src/mcp_tool_call_tests.rs` and run
`cargo test -p codex-core --lib -- --nocapture`:

```rust
#[test]
fn server_declared_read_only_hint_suppresses_approval() {
    assert!(requires_mcp_tool_approval(None));                                   // prompts
    assert!(requires_mcp_tool_approval(Some(&annotations(Some(false), Some(true), None))));
    assert!(!requires_mcp_tool_approval(Some(&annotations(Some(true), None, None))));
    assert!(!requires_mcp_tool_approval(Some(&annotations(Some(true), None, Some(true)))));
}
```

| Server declares | Client behaviour |
|---|---|
| nothing | prompts (safe default) |
| `destructiveHint: true` | prompts |
| `readOnlyHint: true` | **no prompt** |
| `readOnlyHint: true` + `openWorldHint: true` | **no prompt** |

Verified against `openai/codex` at commit `44b857c`, September 2026.

## The part I find interesting

Codex clearly models some server-supplied fields as untrusted. In the same struct
construction that forwards the annotations, `connected_account_email` is gated on the
first-party server name, and elsewhere `connector_id`, `link_id` and `app_name` are taken
only when the server is OpenAI's own hosted apps server:

```rust
connected_account_email: (invocation.server == CODEX_APPS_MCP_SERVER_NAME)
    .then(|| metadata.connected_account_email.clone()).flatten(),
...
annotations: metadata.annotations.as_ref().map(|a| GuardianMcpAnnotations {
    destructive_hint: a.destructive_hint,
    open_world_hint:  a.open_world_hint,
    read_only_hint:   a.read_only_hint,      // not gated
}),
```

The fields that affect *display* are gated on trust. The field that decides *whether the user
is asked at all* is not. Whether that asymmetry is deliberate or incidental, it is the shape
worth noticing: the annotation is the only one of these that changes what happens rather than
what is shown.

## The vendor's position

This is not treated as a defect. Responding to a 2025 report that Codex executed MCP edit
tools under a read-only configuration, the maintainers wrote:

> "MCPs operate outside of the Codex exec sandbox. If you need to guarantee that the sandbox
> is fully respected, you'll need to disable MCPs or add the desired functionality to the MCP.
> Codex has no way to control what commands a MCP server runs."

That is a coherent position. An MCP server is a separate process the user chose to run; the
client cannot constrain it, and the sandbox that confines shell commands does not extend to
it. Under that model, adding a server *is* the trust decision, and the annotation merely
shapes the UX afterwards.

## Where I think the model strains

Two places.

**The rug-pull.** Consent is given once, when the server is added, and is then applied to a
tool listing the server can change at any time. An honest server that later adds
`readOnlyHint: true` to a new tool inherits an approval the user granted to a different
artifact. If adding a server is the trust decision, that decision is made against a snapshot
which the trusted party is free to revise.

**The prompt's own existence.** If adding a server conferred full trust, there would be no
approval flow for its tools. The flow exists because the trust is partial — and its threshold
is then set by the party it constrains. A control that the constrained party can switch off
is doing less work than its presence implies.

Neither observation makes this a vulnerability in the vendor's model, and I am not arguing it
is one. They are the reasons I think "the user chose to add it" carries less weight in
agentic systems than it does for, say, installing a package: the artifact that eventually
runs is not the artifact that was consented to.

## Defensive notes

For client implementers:

- Treat annotations from non-first-party servers as display metadata only; do not let them
  determine whether a user is asked.
- Pin the tool listing at add-time and re-prompt when a server's declared tools or annotations
  change. This defeats the rug-pull without requiring the client to constrain the server.
- Make the trust level explicit and per-server, rather than implicit in the act of adding.

For operators: an MCP server runs outside the agent's sandbox and outside its network
controls. Treat adding one as equivalent to installing software, not to opening a document.

## Prior work

This behaviour is already documented publicly. I found it independently while auditing the
Codex approval paths, then found these:

- `openai/codex` issue #4152 (2025-09-24, closed) — "Codex CLI ignores 'read-only' mode and
  approval policy by executing MCP edit tools", including the maintainer response quoted above.
- Public write-ups on the `readOnlyHint` trust problem in MCP clients generally, and on how
  Codex CLI uses annotations to drive approval decisions.
- The MCP specification's own guidance that annotations are untrusted hints.

No vulnerability report was filed for this, because it is known and accepted behaviour rather
than a defect the vendor intends to fix.
