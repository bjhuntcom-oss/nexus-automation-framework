"""
Attack Graph Engine - Weighted Attack Path Computation

Dynamic weighted directed graph for attack path analysis.
Nodes = assets/identities/services
Edges = exploitable techniques
Weights = probability × impact × noise factor

Algorithms:
- Dijkstra for optimal paths
- A* for heuristic search
- Multi-objective optimization
- Dynamic recalculation on events
"""

import asyncio
import json
import logging
import math
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict


class EdgeType(Enum):
    """Types of attack graph edges."""
    EXPLOIT = "exploit"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_THEFT = "credential_theft"
    PIVOT = "pivot"
    EXFILTRATION = "exfiltration"


class NodeType(Enum):
    """Types of attack graph nodes."""
    HOST = "host"
    SERVICE = "service"
    USER = "user"
    CREDENTIAL = "credential"
    DOMAIN_CONTROLLER = "domain_controller"
    DATABASE = "database"
    WEB_APPLICATION = "web_application"
    NETWORK_SEGMENT = "network_segment"


@dataclass
class GraphNode:
    """Attack graph node with metadata."""
    node_id: str
    node_type: NodeType
    value: float  # Business value 0-1
    defenses: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    network_position: str = ""
    trust_level: float = 0.0
    detection_level: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Attack graph edge with weight calculation."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    technique_id: str
    success_probability: float
    impact_score: float
    stealth_score: float
    detection_risk: float
    time_cost: int  # minutes
    required_tools: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=dict)
    
    @property
    def weight(self) -> float:
        """Calculate edge weight (lower = better)."""
        # Weight = (1 - success_probability) + impact_penalty + detection_penalty + time_penalty
        success_penalty = 1 - self.success_probability
        impact_penalty = self.impact_score * 0.3
        detection_penalty = self.detection_risk * 0.4
        stealth_penalty = (1 - self.stealth_score) * 0.2
        time_penalty = (self.time_cost / 60) * 0.1  # Normalize by hour
        
        return success_penalty + impact_penalty + detection_penalty + stealth_penalty + time_penalty
    
    @property
    def risk_score(self) -> float:
        """Calculate risk score (higher = riskier)."""
        return self.detection_risk * (1 - self.stealth_score) * self.impact_score


class AttackGraphEngine:
    """Main attack graph computation engine."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[Tuple[str, str], GraphEdge] = {}
        self.logger = logging.getLogger("attack_graph")
        
        # Graph metrics cache
        self._centrality_cache: Optional[Dict[str, float]] = None
        self._betweenness_cache: Optional[Dict[str, float]] = None
        self._last_update: Optional[datetime] = None
        
        # Path computation cache
        self._path_cache: Dict[str, List[List[str]]] = {}
        self._cache_timeout = timedelta(minutes=5)
    
    def add_node(self, node: GraphNode) -> bool:
        """Add node to attack graph."""
        try:
            self.nodes[node.node_id] = node
            self.graph.add_node(
                node.node_id,
                node_type=node.node_type.value,
                value=node.value,
                defenses=node.defenses,
                vulnerabilities=node.vulnerabilities,
                trust_level=node.trust_level,
                detection_level=node.detection_level
            )
            
            # Invalidate caches
            self._invalidate_caches()
            
            self.logger.debug(f"Added node {node.node_id} of type {node.node_type.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add node {node.node_id}: {e}")
            return False
    
    def add_edge(self, edge: GraphEdge) -> bool:
        """Add weighted edge to attack graph."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            self.logger.error(f"Edge references non-existent nodes: {edge.source_id} -> {edge.target_id}")
            return False
        
        try:
            edge_key = (edge.source_id, edge.target_id)
            self.edges[edge_key] = edge
            
            self.graph.add_edge(
                edge.source_id,
                edge.target_id,
                weight=edge.weight,
                edge_type=edge.edge_type.value,
                technique_id=edge.technique_id,
                success_probability=edge.success_probability,
                impact_score=edge.impact_score,
                stealth_score=edge.stealth_score,
                detection_risk=edge.detection_risk,
                time_cost=edge.time_cost,
                risk_score=edge.risk_score
            )
            
            # Invalidate caches
            self._invalidate_caches()
            
            self.logger.debug(f"Added edge {edge.source_id} -> {edge.target_id} ({edge.edge_type.value})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add edge {edge.source_id} -> {edge.target_id}: {e}")
            return False
    
    def remove_node(self, node_id: str) -> bool:
        """Remove node and all connected edges."""
        if node_id not in self.nodes:
            return False
        
        try:
            # Remove edges connected to this node
            edges_to_remove = [
                (src, dst) for src, dst in self.edges.keys()
                if src == node_id or dst == node_id
            ]
            
            for edge_key in edges_to_remove:
                del self.edges[edge_key]
            
            # Remove from graph
            self.graph.remove_node(node_id)
            del self.nodes[node_id]
            
            # Invalidate caches
            self._invalidate_caches()
            
            self.logger.debug(f"Removed node {node_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove node {node_id}: {e}")
            return False
    
    def find_optimal_paths(self, source: str, target: str, 
                          algorithm: str = "dijkstra",
                          max_paths: int = 5) -> List[List[str]]:
        """Find optimal attack paths using specified algorithm."""
        if source not in self.nodes or target not in self.nodes:
            return []
        
        # Check cache first
        cache_key = f"{source}->{target}_{algorithm}"
        if cache_key in self._path_cache:
            cached_time, cached_paths = self._path_cache[cache_key]
            if datetime.now() - cached_time < self._cache_timeout:
                return cached_paths
        
        paths = []
        
        try:
            if algorithm == "dijkstra":
                # Shortest path by weight
                try:
                    path = nx.dijkstra_path(self.graph, source, target, weight='weight')
                    paths.append(path)
                except nx.NetworkXNoPath:
                    pass
            
            elif algorithm == "astar":
                # A* search with heuristic
                def heuristic(u, v):
                    # Simple heuristic based on node values and detection levels
                    u_node = self.nodes.get(u, GraphNode(u, NodeType.HOST, 0.5))
                    v_node = self.nodes.get(v, GraphNode(v, NodeType.HOST, 0.5))
                    return (u_node.detection_level + v_node.detection_level) / 2
                
                try:
                    path = nx.astar_path(self.graph, source, target, heuristic=heuristic, weight='weight')
                    paths.append(path)
                except nx.NetworkXNoPath:
                    pass
            
            elif algorithm == "multi_objective":
                # Multi-objective optimization
                paths = self._multi_objective_paths(source, target, max_paths)
            
            elif algorithm == "all_shortest":
                # All shortest paths
                try:
                    all_paths = list(nx.all_shortest_paths(self.graph, source, target, weight='weight'))
                    paths.extend(all_paths[:max_paths])
                except nx.NetworkXNoPath:
                    pass
            
            # Cache results
            self._path_cache[cache_key] = (datetime.now(), paths)
            
        except Exception as e:
            self.logger.error(f"Path finding failed {source} -> {target}: {e}")
        
        return paths
    
    def _multi_objective_paths(self, source: str, target: str, max_paths: int) -> List[List[str]]:
        """Multi-objective path optimization."""
        # Find all simple paths up to reasonable length
        all_paths = []
        try:
            for path in nx.all_simple_paths(self.graph, source, target, cutoff=8):
                if len(path) <= 8:  # Reasonable path length
                    all_paths.append(path)
        except nx.NetworkXNoPath:
            return []
        
        if not all_paths:
            return []
        
        # Score paths on multiple criteria
        scored_paths = []
        for path in all_paths:
            scores = self._score_path_multi_objective(path)
            # Combine scores (lower = better)
            combined_score = (
                scores['weight'] * 0.4 +
                scores['risk'] * 0.3 +
                scores['time'] * 0.2 +
                scores['detection'] * 0.1
            )
            scored_paths.append((combined_score, path))
        
        # Sort and return top paths
        scored_paths.sort(key=lambda x: x[0])
        return [path for _, path in scored_paths[:max_paths]]
    
    def _score_path_multi_objective(self, path: List[str]) -> Dict[str, float]:
        """Score path on multiple objectives."""
        scores = {
            'weight': 0.0,
            'risk': 0.0,
            'time': 0.0,
            'detection': 0.0
        }
        
        for i in range(len(path) - 1):
            edge_key = (path[i], path[i + 1])
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                scores['weight'] += edge.weight
                scores['risk'] += edge.risk_score
                scores['time'] += edge.time_cost
                scores['detection'] += edge.detection_risk
        
        # Normalize by path length
        path_len = len(path) - 1
        if path_len > 0:
            for key in scores:
                scores[key] /= path_len
        
        return scores
    
    def calculate_centrality_metrics(self) -> Dict[str, Dict[str, float]]:
        """Calculate centrality metrics for all nodes."""
        if not self.graph.nodes():
            return {}
        
        metrics = {}
        
        try:
            # Betweenness centrality
            betweenness = nx.betweenness_centrality(self.graph, weight='weight')
            
            # Closeness centrality
            closeness = nx.closeness_centrality(self.graph)
            
            # Eigenvector centrality
            try:
                eigenvector = nx.eigenvector_centrality_numpy(self.graph, weight='weight')
            except:
                eigenvector = {node: 0.0 for node in self.graph.nodes()}
            
            # PageRank
            pagerank = nx.pagerank(self.graph, weight='weight')
            
            # Combine metrics
            for node_id in self.graph.nodes():
                metrics[node_id] = {
                    'betweenness': betweenness.get(node_id, 0.0),
                    'closeness': closeness.get(node_id, 0.0),
                    'eigenvector': eigenvector.get(node_id, 0.0),
                    'pagerank': pagerank.get(node_id, 0.0)
                }
            
            # Cache results
            self._centrality_cache = {node: metrics[node]['betweenness'] for node in metrics}
            self._betweenness_cache = {node: metrics[node]['closeness'] for node in metrics}
            self._last_update = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Centrality calculation failed: {e}")
        
        return metrics
    
    def find_critical_nodes(self, top_k: int = 10) -> List[Tuple[str, float]]:
        """Find most critical nodes by centrality."""
        if not self._centrality_cache:
            self.calculate_centrality_metrics()
        
        if not self._centrality_cache:
            return []
        
        # Sort by betweenness centrality
        sorted_nodes = sorted(
            self._centrality_cache.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_nodes[:top_k]
    
    def find_attack_chains(self, source: str, max_depth: int = 5) -> List[List[str]]:
        """Find all possible attack chains from source."""
        if source not in self.nodes:
            return []
        
        chains = []
        
        def dfs(current: str, path: List[str], visited: Set[str], depth: int):
            if depth >= max_depth:
                return
            
            # Add current chain if length > 1
            if len(path) > 1:
                chains.append(path.copy())
            
            # Explore neighbors
            for neighbor in self.graph.successors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited, depth + 1)
                    path.pop()
                    visited.remove(neighbor)
        
        # Start DFS
        dfs(source, [source], {source}, 0)
        
        return chains
    
    def calculate_attack_surface(self, node_id: str) -> Dict[str, Any]:
        """Calculate attack surface for a node."""
        if node_id not in self.nodes:
            return {}
        
        node = self.nodes[node_id]
        
        # Incoming edges (attack vectors)
        incoming_edges = list(self.graph.predecessors(node_id))
        
        # Outgoing edges (lateral movement)
        outgoing_edges = list(self.graph.successors(node_id))
        
        # Calculate metrics
        attack_surface = {
            'node_id': node_id,
            'node_type': node.node_type.value,
            'incoming_vectors': len(incoming_edges),
            'outgoing_vectors': len(outgoing_edges),
            'total_vectors': len(incoming_edges) + len(outgoing_edges),
            'vulnerability_count': len(node.vulnerabilities),
            'defense_count': len(node.defenses),
            'risk_score': 0.0,
            'exploit_paths': []
        }
        
        # Calculate risk score
        total_risk = 0.0
        edge_count = 0
        
        for pred in incoming_edges:
            edge_key = (pred, node_id)
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                total_risk += edge.risk_score
                edge_count += 1
        
        if edge_count > 0:
            attack_surface['risk_score'] = total_risk / edge_count
        
        # Find exploit paths
        for pred in incoming_edges:
            paths = self.find_optimal_paths(pred, node_id, max_paths=3)
            attack_surface['exploit_paths'].extend(paths)
        
        return attack_surface
    
    def update_edge_weights(self, updates: Dict[str, float]) -> int:
        """Update edge weights based on new information."""
        updated_count = 0
        
        for edge_key_str, new_weight in updates.items():
            try:
                # Parse edge key "source->target"
                source, target = edge_key_str.split("->")
                edge_key = (source, target)
                
                if edge_key in self.edges:
                    # Update the edge in NetworkX graph
                    if self.graph.has_edge(source, target):
                        self.graph[source][target]['weight'] = new_weight
                    
                    updated_count += 1
                    
            except Exception as e:
                self.logger.warning(f"Failed to update edge weight {edge_key_str}: {e}")
        
        if updated_count > 0:
            self._invalidate_caches()
            self.logger.info(f"Updated {updated_count} edge weights")
        
        return updated_count
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get comprehensive graph statistics."""
        stats = {
            'nodes_count': len(self.nodes),
            'edges_count': len(self.edges),
            'is_connected': nx.is_weakly_connected(self.graph),
            'density': nx.density(self.graph),
            'average_path_length': 0.0,
            'diameter': 0,
            'node_types': defaultdict(int),
            'edge_types': defaultdict(int)
        }
        
        try:
            if nx.is_weakly_connected(self.graph):
                stats['average_path_length'] = nx.average_shortest_path_length(self.graph, weight='weight')
                stats['diameter'] = nx.diameter(self.graph.to_undirected())
        except:
            pass
        
        # Count node types
        for node in self.nodes.values():
            stats['node_types'][node.node_type.value] += 1
        
        # Count edge types
        for edge in self.edges.values():
            stats['edge_types'][edge.edge_type.value] += 1
        
        return dict(stats)
    
    def export_graph(self, format: str = "json") -> Union[str, Dict]:
        """Export graph in specified format."""
        if format == "json":
            return self._export_json()
        elif format == "gexf":
            return self._export_gexf()
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self) -> Dict:
        """Export graph as JSON."""
        export_data = {
            'metadata': {
                'exported_at': datetime.now().isoformat(),
                'nodes_count': len(self.nodes),
                'edges_count': len(self.edges)
            },
            'nodes': [],
            'edges': []
        }
        
        # Export nodes
        for node_id, node in self.nodes.items():
            node_data = {
                'id': node_id,
                'type': node.node_type.value,
                'value': node.value,
                'defenses': node.defenses,
                'vulnerabilities': node.vulnerabilities,
                'trust_level': node.trust_level,
                'detection_level': node.detection_level,
                'metadata': node.metadata
            }
            export_data['nodes'].append(node_data)
        
        # Export edges
        for (source, target), edge in self.edges.items():
            edge_data = {
                'source': source,
                'target': target,
                'type': edge.edge_type.value,
                'technique_id': edge.technique_id,
                'success_probability': edge.success_probability,
                'impact_score': edge.impact_score,
                'stealth_score': edge.stealth_score,
                'detection_risk': edge.detection_risk,
                'time_cost': edge.time_cost,
                'weight': edge.weight,
                'risk_score': edge.risk_score,
                'required_tools': edge.required_tools,
                'prerequisites': edge.prerequisites,
                'side_effects': edge.side_effects
            }
            export_data['edges'].append(edge_data)
        
        return export_data
    
    def _export_gexf(self) -> str:
        """Export graph as GEXF for visualization."""
        import io
        
        # Create a copy with attributes for GEXF export
        export_graph = nx.DiGraph()
        
        # Add nodes with attributes
        for node_id, node in self.nodes.items():
            export_graph.add_node(
                node_id,
                label=node_id,
                type=node.node_type.value,
                value=node.value,
                trust_level=node.trust_level,
                detection_level=node.detection_level
            )
        
        # Add edges with attributes
        for (source, target), edge in self.edges.items():
            export_graph.add_edge(
                source, target,
                weight=edge.weight,
                type=edge.edge_type.value,
                technique=edge.technique_id,
                risk=edge.risk_score
            )
        
        # Export to GEXF
        output = io.StringIO()
        nx.write_gexf(export_graph, output)
        return output.getvalue()
    
    def _invalidate_caches(self):
        """Invalidate all caches."""
        self._centrality_cache = None
        self._betweenness_cache = None
        self._path_cache.clear()
        self._last_update = None
