from prometheus_client import Counter, Gauge, Histogram, start_http_server

MESSAGES_IN = Counter("raven_messages_consumed_total", "Messages consumed", ["service", "topic"])
MESSAGES_OUT = Counter("raven_messages_produced_total", "Messages produced", ["service", "topic"])
ERRORS = Counter("raven_errors_total", "Unhandled errors", ["service", "stage"])
QUARANTINED = Counter("raven_quarantined_total", "Records quarantined", ["source", "reason"])
GUARD_BLOCKS = Counter("raven_guard_blocks_total", "Prompt-guard interventions", ["rule"])
DECISIONS = Counter("raven_agent_decisions_total", "Agent decisions", ["action"])
STAGE_LATENCY = Histogram("raven_stage_seconds", "Stage processing time", ["service", "stage"])
MODEL_TRUST = Gauge("raven_model_trust_score", "Rolling calibration score", ["model"])
GRAPH_NODES = Gauge("raven_graph_nodes", "Nodes in the attack graph", ["label"])
BACKLOG = Gauge("raven_backlog", "Pending items", ["queue"])


def serve(port: int) -> None:
    start_http_server(port)
