# Architecture

Room has two planes.

## Control plane

The dashboard and admin API publish rules. Every publish creates an immutable
`RulesetVersion` with a version and hash. Rollback is an active-version pointer
change, not a mutation of old rules.

```text
Dashboard / API client
  -> RuleAdminService
  -> file store today, database later
  -> immutable ruleset versions
```

## Agent plane

Agents do not write rules. They fetch or watch active rulesets and evaluate
plans/diffs through the MCP sidecar or hook runner.

```text
Coding agent
  -> MCP tool or lifecycle hook
  -> room-mcp / roomctl
  -> AgentRulesService
  -> active ruleset
```

`roomctl` and `room-mcp` cache the latest fetched ruleset locally. Hook
evaluation uses that cache as a fallback when the control plane is offline, so a
short outage does not remove guardrails from the agent loop.

For push-style updates, `AgentRulesService.WatchRuleset` streams new active
ruleset versions, and `roomctl watch-rules` persists those updates into the
same local cache used by hooks.

## Why both MCP and hooks

MCP is the advisory interface: it lets the model ask for guidance before making
an implementation choice.

Hooks are the deterministic interface: they run during lifecycle events and can
block or add feedback even if the model forgets to call the MCP tool.
