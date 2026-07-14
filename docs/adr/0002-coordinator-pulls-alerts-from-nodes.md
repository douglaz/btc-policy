# Alerts are pulled by the coordinator, not pushed by nodes

Nodes make no outbound connections. Each vault node queues its alerts (watchtower hits, refusals) and its log locally and exposes them on a pull endpoint; the coordinator polls all nodes and surfaces alerts to the user. The coordinator is trusted for this, as it is for spend orchestration in the MVP.

## Considered Options

- **Per-node user-owned push sink (webhook per node)** — rejected for the MVP: five alert channels to configure, and it breaks the "nodes only answer requests / only watch the blockchain" shape.

## Consequences

- Accepted risk, stated openly: a compromised coordinator can suppress alerts, and alert latency is bounded by coordinator uptime/polling. This extends the eng-review D11 posture (coordinator-side alerting) to watchtower alerts.
- Watchtower *detection* remains n-way independent (each node watches its own chain view); only *delivery* is centralized. Per-node push sinks remain a possible post-MVP hardening without changing detection.
- Nodes need a bounded, persistent-enough alert queue and a cursor-based pull API (e.g., `GET /events?since=`).
