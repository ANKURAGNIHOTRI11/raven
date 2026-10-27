"""Canonical Kafka topic names. Nothing publishes to a literal string."""

RAW_DOCUMENTS = "raven.raw.documents"
NORMALIZED_VULNS = "raven.norm.vulnerabilities"
QUARANTINE = "raven.quarantine.records"
ASSET_EVENTS = "raven.assets.events"
GRAPH_UPDATES = "raven.graph.updates"
GRAPH_SIGNALS = "raven.graph.signals"
RISK_SCORED = "raven.risk.scored"
AGENT_TASKS = "raven.agents.tasks"
AGENT_DECISIONS = "raven.agents.decisions"
REMEDIATIONS = "raven.remediation.proposed"
HUMAN_QUEUE = "raven.human.queue"
FEEDBACK = "raven.feedback.events"

ALL_TOPICS = [
    RAW_DOCUMENTS,
    NORMALIZED_VULNS,
    QUARANTINE,
    ASSET_EVENTS,
    GRAPH_UPDATES,
    GRAPH_SIGNALS,
    RISK_SCORED,
    AGENT_TASKS,
    AGENT_DECISIONS,
    REMEDIATIONS,
    HUMAN_QUEUE,
    FEEDBACK,
]
