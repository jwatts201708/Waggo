from __future__ import annotations

import json
import logging
import math
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple
from datetime import datetime, timezone

from app.api.schemas import NeuroStepRequest, NeuroGraphSnapshot

logger = logging.getLogger(__name__)

@dataclass
class Node:
    activation: float = 0.0
    bias: float = 0.0
    last_input: float = 0.0

@dataclass
class Edge:
    weight: float = 0.0
    last_delta: float = 0.0

@dataclass
class NeuroGraph:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: Dict[Tuple[str, str], Edge] = field(default_factory=dict)

    def ensure_node(self, node_id: str) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(activation=0.0, bias=0.0)

    def ensure_edge(self, src: str, dst: str) -> None:
        self.ensure_node(src); self.ensure_node(dst)
        key = (src, dst)
        if key not in self.edges:
            # tiny random init avoids symmetry lock
            self.edges[key] = Edge(weight=(secrets.randbelow(2000) - 1000) / 1_000_000.0)

    @staticmethod
    def _sigmoid(x: float) -> float:
        # stable-ish sigmoid
        if x >= 0:
            z = math.exp(-x)
            return 1.0 / (1.0 + z)
        z = math.exp(x)
        return z / (1.0 + z)

    def step(self, req: NeuroStepRequest) -> NeuroGraphSnapshot:
        cfg = req.config
        # Inject stimuli
        for stim in req.stimuli:
            self.ensure_node(stim.node_id)
            self.nodes[stim.node_id].last_input += stim.value

        # Propagate activations
        for _ in range(cfg.propagation_steps):
            next_act: Dict[str, float] = {nid: 0.0 for nid in self.nodes}
            # accumulate weighted inputs
            for (src, dst), edge in self.edges.items():
                s = self.nodes[src].activation
                next_act[dst] += s * edge.weight

            # apply activation function + bias + external input
            for nid, node in self.nodes.items():
                raw = next_act.get(nid, 0.0) + node.bias + node.last_input
                node.activation = self._sigmoid(raw)
                # decay external input each propagation step
                node.last_input *= (1.0 - cfg.decay)

        # Hebbian-ish learning (Δw = lr * a_src * a_dst, with decay)
        for (src, dst), edge in self.edges.items():
            a_s = self.nodes[src].activation
            a_d = self.nodes[dst].activation
            delta = cfg.learning_rate * (a_s * a_d)
            edge.last_delta = delta
            edge.weight = (edge.weight * (1.0 - cfg.decay)) + delta

        # snapshot
        snap_id = "NS-" + secrets.token_hex(8)
        ts = datetime.now(timezone.utc).isoformat()

        nodes_out: Dict[str, Dict[str, Any]] = {
            nid: {"activation": n.activation, "bias": n.bias, "last_input": n.last_input}
            for nid, n in self.nodes.items()
        }
        edges_out: Dict[str, Dict[str, Any]] = {
            f"{src}->{dst}": {"weight": e.weight, "last_delta": e.last_delta}
            for (src, dst), e in self.edges.items()
        }

        logger.info("neurosync_step",
                    extra={"snapshot_id": snap_id, "nodes": len(nodes_out), "edges": len(edges_out)})

        return NeuroGraphSnapshot(
            snapshot_id=snap_id,
            timestamp_utc=ts,
            nodes=nodes_out,
            edges=edges_out,
        )

    def to_json(self) -> tuple[str, str]:
        nodes_json = json.dumps({k: vars(v) for k, v in self.nodes.items()})
        edges_json = json.dumps({f"{a}->{b}": vars(e) for (a, b), e in self.edges.items()})
        return nodes_json, edges_json

    def add_dense_edges(self) -> None:
        # A small starter topology: connect a few canonical nodes
        canonical = ["sense", "predict", "decide", "act", "audit"]
        for i in range(len(canonical) - 1):
            self.ensure_edge(canonical[i], canonical[i + 1])
        # add a feedback loop
        self.ensure_edge("audit", "predict")
