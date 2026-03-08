// Package graph provides identity relationship mapping and blast radius analysis.
// This is what makes nexora-cli UNIQUE - no other scanner traces identity relationships.
package graph

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// IdentityNode represents a non-human identity in the graph
type IdentityNode struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        NodeType          `json:"type"`
	Provider    string            `json:"provider"`
	Risk        RiskLevel         `json:"risk"`
	Permissions []string          `json:"permissions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// NodeType represents the type of identity node
type NodeType string

const (
	NodeTypeGitHubApp         NodeType = "github_app"
	NodeTypeGitHubWorkflow    NodeType = "github_workflow"
	NodeTypeGitHubSecret      NodeType = "github_secret"
	NodeTypeGitHubOIDC        NodeType = "github_oidc"
	NodeTypeDeployKey         NodeType = "deploy_key"
	NodeTypeAWSRole           NodeType = "aws_iam_role"
	NodeTypeAWSUser           NodeType = "aws_iam_user"
	NodeTypeAWSAccessKey      NodeType = "aws_access_key"
	NodeTypeAWSResource       NodeType = "aws_resource"
	NodeTypeK8sServiceAccount NodeType = "k8s_service_account"
	NodeTypeK8sSecret         NodeType = "k8s_secret"
	NodeTypeK8sRole           NodeType = "k8s_role"
)

// RiskLevel indicates the risk level of a node
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskInfo     RiskLevel = "info"
)

// Edge represents a relationship between two identity nodes
type Edge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Relation Relation `json:"relation"`
	Via      string   `json:"via,omitempty"`
}

// Relation describes the type of relationship
type Relation string

const (
	RelationCanAssume  Relation = "can_assume"
	RelationCanAccess  Relation = "can_access"
	RelationCanTrigger Relation = "can_trigger"
	RelationCanRead    Relation = "can_read"
	RelationCanWrite   Relation = "can_write"
	RelationCanDelete  Relation = "can_delete"
	RelationCreates    Relation = "creates"
	RelationTrustsOIDC Relation = "trusts_oidc"
	RelationUsesSecret Relation = "uses_secret"
	RelationBoundTo    Relation = "bound_to"
)

// IdentityGraph represents the complete identity relationship graph
type IdentityGraph struct {
	Nodes      map[string]*IdentityNode `json:"nodes"`
	Edges      []Edge                   `json:"edges"`
	adjList    map[string][]Edge
	reverseAdj map[string][]Edge
}

// NewIdentityGraph creates a new empty identity graph
func NewIdentityGraph() *IdentityGraph {
	return &IdentityGraph{
		Nodes:      make(map[string]*IdentityNode),
		Edges:      []Edge{},
		adjList:    make(map[string][]Edge),
		reverseAdj: make(map[string][]Edge),
	}
}

// AddNode adds an identity node to the graph
func (g *IdentityGraph) AddNode(node *IdentityNode) {
	if node.ID == "" {
		node.ID = generateNodeID(node)
	}
	g.Nodes[node.ID] = node
}

// AddEdge adds a relationship edge to the graph
func (g *IdentityGraph) AddEdge(from, to string, relation Relation, via string) {
	edge := Edge{
		From:     from,
		To:       to,
		Relation: relation,
		Via:      via,
	}
	g.Edges = append(g.Edges, edge)
	g.adjList[from] = append(g.adjList[from], edge)
	g.reverseAdj[to] = append(g.reverseAdj[to], edge)
}

// BlastRadius calculates what can be reached if a given identity is compromised
func (g *IdentityGraph) BlastRadius(startNodeID string) *BlastRadiusResult {
	result := &BlastRadiusResult{
		StartNode:      startNodeID,
		ReachableNodes: make(map[string]*ReachableNode),
		MaxDepth:       0,
		CriticalPath:   []string{},
	}

	visited := make(map[string]bool)
	queue := []struct {
		nodeID string
		depth  int
		path   []string
	}{{startNodeID, 0, []string{startNodeID}}}

	var criticalNodes []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.nodeID] {
			continue
		}
		visited[current.nodeID] = true

		node := g.Nodes[current.nodeID]
		if node == nil {
			continue
		}

		if current.nodeID != startNodeID {
			result.ReachableNodes[current.nodeID] = &ReachableNode{
				Node:  node,
				Depth: current.depth,
				Path:  current.path,
			}

			if node.Risk == RiskCritical || node.Risk == RiskHigh {
				criticalNodes = append(criticalNodes, current.nodeID)
				if len(result.CriticalPath) == 0 || current.depth < len(result.CriticalPath) {
					result.CriticalPath = current.path
				}
			}
		}

		if current.depth > result.MaxDepth {
			result.MaxDepth = current.depth
		}

		for _, edge := range g.adjList[current.nodeID] {
			if !visited[edge.To] {
				newPath := make([]string, len(current.path))
				copy(newPath, current.path)
				newPath = append(newPath, edge.To)
				queue = append(queue, struct {
					nodeID string
					depth  int
					path   []string
				}{edge.To, current.depth + 1, newPath})
			}
		}
	}

	result.RiskScore = g.calculateBlastRadiusRisk(result)
	result.CriticalNodesReached = len(criticalNodes)

	return result
}

// BlastRadiusResult contains the analysis of what's reachable from a compromised identity
type BlastRadiusResult struct {
	StartNode            string                    `json:"start_node"`
	ReachableNodes       map[string]*ReachableNode `json:"reachable_nodes"`
	MaxDepth             int                       `json:"max_depth"`
	CriticalPath         []string                  `json:"critical_path"`
	CriticalNodesReached int                       `json:"critical_nodes_reached"`
	RiskScore            float64                   `json:"risk_score"`
}

// ReachableNode represents a node that can be reached from the start
type ReachableNode struct {
	Node  *IdentityNode `json:"node"`
	Depth int           `json:"depth"`
	Path  []string      `json:"path"`
}

func (g *IdentityGraph) calculateBlastRadiusRisk(result *BlastRadiusResult) float64 {
	if len(result.ReachableNodes) == 0 {
		return 0
	}

	var score float64

	score += float64(len(result.ReachableNodes)) * 0.1

	for _, rn := range result.ReachableNodes {
		switch rn.Node.Risk {
		case RiskCritical:
			score += 1.0
		case RiskHigh:
			score += 0.7
		case RiskMedium:
			score += 0.3
		case RiskLow:
			score += 0.1
		}
	}

	if result.MaxDepth > 0 && result.CriticalNodesReached > 0 {
		shortestCritical := result.MaxDepth
		for _, rn := range result.ReachableNodes {
			if (rn.Node.Risk == RiskCritical || rn.Node.Risk == RiskHigh) && rn.Depth < shortestCritical {
				shortestCritical = rn.Depth
			}
		}
		if shortestCritical <= 2 {
			score *= 1.5
		}
	}

	if score > 10 {
		score = 10
	}
	return score
}

// FindAllPaths finds all paths between two nodes
func (g *IdentityGraph) FindAllPaths(from, to string, maxDepth int) [][]string {
	var paths [][]string
	visited := make(map[string]bool)

	var dfs func(current string, path []string, depth int)
	dfs = func(current string, path []string, depth int) {
		if depth > maxDepth {
			return
		}
		if current == to {
			pathCopy := make([]string, len(path))
			copy(pathCopy, path)
			paths = append(paths, pathCopy)
			return
		}
		if visited[current] {
			return
		}
		visited[current] = true
		defer func() { visited[current] = false }()

		for _, edge := range g.adjList[current] {
			dfs(edge.To, append(path, edge.To), depth+1)
		}
	}

	dfs(from, []string{from}, 0)
	return paths
}

// GetHighRiskPaths returns all paths that lead to critical/high risk nodes
func (g *IdentityGraph) GetHighRiskPaths() []HighRiskPath {
	var results []HighRiskPath

	var criticalNodes []string
	for id, node := range g.Nodes {
		if node.Risk == RiskCritical || node.Risk == RiskHigh {
			criticalNodes = append(criticalNodes, id)
		}
	}

	entryPoints := g.findEntryPoints()

	for _, entry := range entryPoints {
		for _, critical := range criticalNodes {
			if entry == critical {
				continue
			}
			paths := g.FindAllPaths(entry, critical, 5)
			for _, path := range paths {
				results = append(results, HighRiskPath{
					EntryPoint: entry,
					TargetNode: critical,
					Path:       path,
					HopCount:   len(path) - 1,
					EntryRisk:  g.Nodes[entry].Risk,
					TargetRisk: g.Nodes[critical].Risk,
				})
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].HopCount < results[j].HopCount
	})

	return results
}

// HighRiskPath represents a path from an entry point to a critical resource
type HighRiskPath struct {
	EntryPoint string    `json:"entry_point"`
	TargetNode string    `json:"target_node"`
	Path       []string  `json:"path"`
	HopCount   int       `json:"hop_count"`
	EntryRisk  RiskLevel `json:"entry_risk"`
	TargetRisk RiskLevel `json:"target_risk"`
}

func (g *IdentityGraph) findEntryPoints() []string {
	var entryPoints []string
	for id, node := range g.Nodes {
		switch node.Type {
		case NodeTypeGitHubApp, NodeTypeGitHubWorkflow, NodeTypeDeployKey, NodeTypeGitHubOIDC:
			entryPoints = append(entryPoints, id)
		}
	}
	return entryPoints
}

// ToDOT exports the graph in DOT format for visualization
func (g *IdentityGraph) ToDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph IdentityGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box];\n\n")

	for id, node := range g.Nodes {
		fillcolor := "white"
		switch node.Risk {
		case RiskCritical:
			fillcolor = "#ff6b6b"
		case RiskHigh:
			fillcolor = "#ffa502"
		case RiskMedium:
			fillcolor = "#ffd93d"
		case RiskLow:
			fillcolor = "#6bcf7f"
		}

		shape := "box"
		switch node.Type {
		case NodeTypeAWSResource, NodeTypeK8sSecret:
			shape = "cylinder"
		case NodeTypeGitHubWorkflow:
			shape = "hexagon"
		}

		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n(%s)\" shape=%s style=filled fillcolor=\"%s\"];\n",
			id, node.Name, node.Type, shape, fillcolor))
	}

	sb.WriteString("\n")

	for _, edge := range g.Edges {
		color := "black"
		switch edge.Relation {
		case RelationCanAssume, RelationTrustsOIDC:
			color = "blue"
		case RelationCanDelete, RelationCanWrite:
			color = "red"
		case RelationCanRead:
			color = "green"
		}

		label := string(edge.Relation)
		if edge.Via != "" {
			label += "\\n(" + edge.Via + ")"
		}

		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\" color=\"%s\"];\n",
			edge.From, edge.To, label, color))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ToMermaid exports the graph in Mermaid format for markdown rendering
func (g *IdentityGraph) ToMermaid() string {
	var sb strings.Builder
	sb.WriteString("```mermaid\ngraph LR\n")

	for id, node := range g.Nodes {
		shape := "[\"%s\"]"
		switch node.Type {
		case NodeTypeAWSResource, NodeTypeK8sSecret:
			shape = "[(\"%s\")]"
		case NodeTypeGitHubWorkflow:
			shape = "{{\"%s\"}}"
		}

		sb.WriteString(fmt.Sprintf("  %s%s\n", id, fmt.Sprintf(shape, node.Name)))
	}

	for _, edge := range g.Edges {
		arrow := "-->"
		switch edge.Relation {
		case RelationCanDelete, RelationCanWrite:
			arrow = "==>"
		}

		sb.WriteString(fmt.Sprintf("  %s %s|%s| %s\n", edge.From, arrow, edge.Relation, edge.To))
	}

	sb.WriteString("\n  classDef critical fill:#ff6b6b\n")
	sb.WriteString("  classDef high fill:#ffa502\n")
	sb.WriteString("  classDef medium fill:#ffd93d\n")

	for id, node := range g.Nodes {
		switch node.Risk {
		case RiskCritical:
			sb.WriteString(fmt.Sprintf("  class %s critical\n", id))
		case RiskHigh:
			sb.WriteString(fmt.Sprintf("  class %s high\n", id))
		case RiskMedium:
			sb.WriteString(fmt.Sprintf("  class %s medium\n", id))
		}
	}

	sb.WriteString("```\n")
	return sb.String()
}

func generateNodeID(node *IdentityNode) string {
	raw := fmt.Sprintf("%s|%s|%s", node.Provider, node.Type, node.Name)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:8])
}

// Summary returns a text summary of the graph
func (g *IdentityGraph) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Identity Graph: %d nodes, %d edges\n\n", len(g.Nodes), len(g.Edges)))

	typeCount := make(map[NodeType]int)
	riskCount := make(map[RiskLevel]int)
	for _, node := range g.Nodes {
		typeCount[node.Type]++
		riskCount[node.Risk]++
	}

	sb.WriteString("By Type:\n")
	for t, c := range typeCount {
		sb.WriteString(fmt.Sprintf("  %-25s %d\n", t, c))
	}

	sb.WriteString("\nBy Risk:\n")
	for _, r := range []RiskLevel{RiskCritical, RiskHigh, RiskMedium, RiskLow, RiskInfo} {
		if c, ok := riskCount[r]; ok {
			sb.WriteString(fmt.Sprintf("  %-10s %d\n", r, c))
		}
	}

	return sb.String()
}
