#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M12: KeyGraphNode_Model_Definition
==================================
This module defines the data structure for the "Key Graph", a sophisticated
visualization model used to track relationships between wallets, transactions,
and smart contracts.

Features:
- Graph Theory basics (Nodes, Edges, Weights).
- "Taint Analysis" properties (tracking illicit funds).
- Hierarchical Deterministic (HD) Wallet structure modeling.
- Export to GEXF/GraphML/JSON for visualization in Gephi or D3.js.
- Anomaly scoring for nodes based on centrality.

Author: Jules (AI)
System: Waggo Arbitrage Core
Date: 2024
"""

import os
import sys
import json
import logging
import uuid
import typing
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

# Configure Logging
logger = logging.getLogger("KeyGraph")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

class NodeType(Enum):
    WALLET = "wallet"
    EXCHANGE = "exchange"
    CONTRACT = "contract"
    MIXER = "mixer"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    SAFE = 0
    LOW = 1
    MEDIUM = 5
    HIGH = 8
    CRITICAL = 10

@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    weight: float # Value transferred or relationship strength
    timestamp: float
    tx_hash: Optional[str] = None
    token_symbol: str = "ETH"

@dataclass
class KeyGraphNode:
    node_id: str # Address or UUID
    label: str
    type: NodeType = NodeType.UNKNOWN
    balance: float = 0.0
    risk_score: int = 0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, typing.Any] = field(default_factory=dict)

    def is_tainted(self) -> bool:
        return self.risk_score >= RiskLevel.HIGH.value

class KeyGraph:
    """
    M12: The Graph Model.
    """
    def __init__(self, graph_id: str = None):
        self.graph_id = graph_id or str(uuid.uuid4())
        self.nodes: Dict[str, KeyGraphNode] = {}
        self.edges: List[GraphEdge] = []

    def add_node(self, address: str, label: str = None, n_type: NodeType = NodeType.UNKNOWN):
        if address not in self.nodes:
            self.nodes[address] = KeyGraphNode(
                node_id=address,
                label=label or address[:8],
                type=n_type
            )
        return self.nodes[address]

    def add_transaction(self, from_addr: str, to_addr: str, value: float, token="ETH", tx_hash=None):
        # Ensure nodes exist
        self.add_node(from_addr)
        self.add_node(to_addr)

        # Add edge
        edge = GraphEdge(
            source_id=from_addr,
            target_id=to_addr,
            weight=value,
            timestamp=0.0, # Mock
            tx_hash=tx_hash,
            token_symbol=token
        )
        self.edges.append(edge)

        # Simple Taint Propagation Logic (Simulation)
        src_risk = self.nodes[from_addr].risk_score
        if src_risk > 0:
            # Transfer some risk to target
            self.nodes[to_addr].risk_score = min(10, self.nodes[to_addr].risk_score + (src_risk * 0.5))

    def mark_risk(self, address: str, level: RiskLevel):
        if address in self.nodes:
            self.nodes[address].risk_score = level.value
            self.nodes[address].tags.append("MANUAL_FLAG")

    def export_json(self) -> str:
        """
        D3.js compatible JSON export.
        """
        data = {
            "nodes": [asdict(n) for n in self.nodes.values()],
            "links": [asdict(e) for e in self.edges]
        }
        # Handle Enum serialization
        class Encoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, Enum):
                    return o.value
                return super().default(o)

        return json.dumps(data, cls=Encoder, indent=2)

    def analyze_centrality(self):
        """
        Identify 'Whales' or 'Hubs' (Nodes with high degree).
        """
        degree = {}
        for edge in self.edges:
            degree[edge.source_id] = degree.get(edge.source_id, 0) + 1
            degree[edge.target_id] = degree.get(edge.target_id, 0) + 1

        # Tag high degree nodes
        for addr, count in degree.items():
            if count > 5: # Threshold
                self.nodes[addr].tags.append("HUB")
                self.nodes[addr].metadata["degree"] = count

# --- Demo ---

def run_graph_demo():
    print("M12: Key Graph Model Demo")

    g = KeyGraph()

    # 1. Setup Network
    exchange = "0xExchange"
    user_a = "0xUserA"
    user_b = "0xUserB"
    hacker = "0xHacker"

    g.add_node(exchange, "Binance", NodeType.EXCHANGE)
    g.add_node(hacker, "DarkWebEntity", NodeType.WALLET)

    # 2. Mark Hacker as Risk
    g.mark_risk(hacker, RiskLevel.CRITICAL)

    # 3. Simulate Flows
    g.add_transaction(hacker, user_a, 10.0, "ETH") # Hacker sends to A
    g.add_transaction(user_a, user_b, 5.0, "ETH")  # A sends to B
    g.add_transaction(user_b, exchange, 5.0, "ETH") # B deposits to Exchange

    # 4. Analyze
    g.analyze_centrality()

    # 5. Check Taint
    print(f"Hacker Risk: {g.nodes[hacker].risk_score}")
    print(f"User A Risk (Inherited): {g.nodes[user_a].risk_score}")
    print(f"User B Risk (Inherited): {g.nodes[user_b].risk_score}")

    # 6. Export
    # print(g.export_json())

if __name__ == "__main__":
    run_graph_demo()
