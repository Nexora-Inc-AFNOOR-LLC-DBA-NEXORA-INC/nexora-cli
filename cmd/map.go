package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	gogithub "github.com/google/go-github/v60/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/Nexora-NHI/nexora-cli/internal/graph"
)

var (
	mapOrg       string
	mapRepo      string
	mapToken     string
	mapOutput    string
	mapFormat    string
	mapBlastFrom string
)

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Map identity relationships and calculate blast radius",
	Long: `Build an identity relationship graph showing what can access what.

This is what makes nexora unique - no other scanner traces relationships between:
- GitHub workflows → secrets → AWS roles → resources
- GitHub Apps → repos → deployment targets
- Service accounts → permissions → data

Use cases:
  • Blast radius: "If this identity is compromised, what can attacker reach?"
  • Attack paths: "What's the shortest path from GitHub to production data?"
  • Over-privilege: "Which identities can reach critical resources?"

Examples:
  # Map entire org
  nexora map --org my-org

  # Map single repo
  nexora map --repo owner/repo

  # Calculate blast radius for specific identity
  nexora map --org my-org --blast-from "workflow-ci"

  # Export as DOT for visualization
  nexora map --org my-org --format dot --output graph.dot
  dot -Tpng graph.dot -o identity-map.png`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if mapOrg == "" && mapRepo == "" {
			return fmt.Errorf("--org or --repo required")
		}
		if mapToken == "" {
			mapToken = os.Getenv("GITHUB_TOKEN")
		}
		if mapToken == "" {
			return fmt.Errorf("GitHub token required: use --token or set GITHUB_TOKEN")
		}
		return nil
	},
	RunE: runMap,
}

func runMap(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: mapToken})
	tc := oauth2.NewClient(ctx, ts)
	client := gogithub.NewClient(tc)

	builder := graph.NewGitHubGraphBuilder(client)

	fmt.Println("Building identity relationship graph...")
	fmt.Println("This analyzes workflows, secrets, apps, and their connections.")
	fmt.Println()

	var identityGraph *graph.IdentityGraph
	var err error

	if mapRepo != "" {
		parts := strings.SplitN(mapRepo, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("repo must be in owner/repo format")
		}
		identityGraph, err = builder.BuildRepoGraph(ctx, parts[0], parts[1])
	} else {
		identityGraph, err = builder.BuildOrgGraph(ctx, mapOrg)
	}

	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Printf("✅ Graph built: %d nodes, %d edges\n\n", len(identityGraph.Nodes), len(identityGraph.Edges))
	fmt.Println(identityGraph.Summary())

	if mapBlastFrom != "" {
		var targetNode string
		for id, node := range identityGraph.Nodes {
			if strings.Contains(strings.ToLower(node.Name), strings.ToLower(mapBlastFrom)) ||
				strings.Contains(strings.ToLower(id), strings.ToLower(mapBlastFrom)) {
				targetNode = id
				break
			}
		}

		if targetNode == "" {
			fmt.Printf("⚠️  No node found matching '%s'\n", mapBlastFrom)
			fmt.Println("Available nodes:")
			for id, node := range identityGraph.Nodes {
				fmt.Printf("  - %s (%s)\n", node.Name, id)
			}
			return nil
		}

		fmt.Printf("\n🎯 BLAST RADIUS ANALYSIS: %s\n", identityGraph.Nodes[targetNode].Name)
		fmt.Println(strings.Repeat("═", 60))

		result := identityGraph.BlastRadius(targetNode)
		printBlastRadius(identityGraph, result)
	} else {
		paths := identityGraph.GetHighRiskPaths()
		if len(paths) > 0 {
			fmt.Println("\n🚨 HIGH-RISK ATTACK PATHS:")
			fmt.Println(strings.Repeat("═", 60))

			shown := 0
			for _, path := range paths {
				if shown >= 5 {
					fmt.Printf("\n... and %d more paths (use --format json for full list)\n", len(paths)-5)
					break
				}

				fmt.Printf("\n%s → %s (%d hops)\n",
					identityGraph.Nodes[path.EntryPoint].Name,
					identityGraph.Nodes[path.TargetNode].Name,
					path.HopCount)

				for i, nodeID := range path.Path {
					node := identityGraph.Nodes[nodeID]
					prefix := "  "
					if i == len(path.Path)-1 {
						prefix = "  └─"
					} else {
						prefix = "  ├─"
					}
					risk := ""
					if node.Risk == graph.RiskCritical || node.Risk == graph.RiskHigh {
						risk = fmt.Sprintf(" [%s]", node.Risk)
					}
					fmt.Printf("%s %s%s\n", prefix, node.Name, risk)
				}
				shown++
			}
		}
	}

	if mapOutput != "" {
		var data []byte
		switch mapFormat {
		case "dot":
			data = []byte(identityGraph.ToDOT())
		case "mermaid":
			data = []byte(identityGraph.ToMermaid())
		default:
			return fmt.Errorf("unsupported format: %s (use dot or mermaid)", mapFormat)
		}

		if err := os.WriteFile(mapOutput, data, 0644); err != nil {
			return err
		}
		fmt.Printf("\n📄 Graph exported to: %s\n", mapOutput)

		if mapFormat == "dot" {
			fmt.Println("\nVisualize with:")
			fmt.Printf("  dot -Tpng %s -o graph.png\n", mapOutput)
			fmt.Printf("  dot -Tsvg %s -o graph.svg\n", mapOutput)
		}
	}

	return nil
}

func printBlastRadius(g *graph.IdentityGraph, result *graph.BlastRadiusResult) {
	fmt.Printf("\nRisk Score: %.1f/10\n", result.RiskScore)
	fmt.Printf("Reachable Nodes: %d\n", len(result.ReachableNodes))
	fmt.Printf("Max Depth: %d hops\n", result.MaxDepth)
	fmt.Printf("Critical/High Resources Reachable: %d\n", result.CriticalNodesReached)

	if len(result.CriticalPath) > 1 {
		fmt.Printf("\nShortest Path to Critical Resource:\n")
		for i, nodeID := range result.CriticalPath {
			node := g.Nodes[nodeID]
			indent := strings.Repeat("  ", i)
			risk := ""
			if node.Risk == graph.RiskCritical {
				risk = " ⚠️  CRITICAL"
			} else if node.Risk == graph.RiskHigh {
				risk = " ⚠️  HIGH"
			}
			fmt.Printf("%s└─ %s (%s)%s\n", indent, node.Name, node.Type, risk)
		}
	}

	if len(result.ReachableNodes) > 0 {
		fmt.Println("\nReachable Resources by Risk:")

		byRisk := make(map[graph.RiskLevel][]*graph.ReachableNode)
		for _, rn := range result.ReachableNodes {
			byRisk[rn.Node.Risk] = append(byRisk[rn.Node.Risk], rn)
		}

		for _, risk := range []graph.RiskLevel{graph.RiskCritical, graph.RiskHigh, graph.RiskMedium, graph.RiskLow} {
			nodes := byRisk[risk]
			if len(nodes) == 0 {
				continue
			}
			fmt.Printf("\n  [%s] (%d)\n", strings.ToUpper(string(risk)), len(nodes))
			for _, rn := range nodes {
				fmt.Printf("    • %s (depth: %d)\n", rn.Node.Name, rn.Depth)
			}
		}
	}
}

func init() {
	rootCmd.AddCommand(mapCmd)

	mapCmd.Flags().StringVar(&mapOrg, "org", "", "GitHub organization to map")
	mapCmd.Flags().StringVar(&mapRepo, "repo", "", "Single repository to map (owner/repo)")
	mapCmd.Flags().StringVar(&mapToken, "token", "", "GitHub token (or set GITHUB_TOKEN)")
	mapCmd.Flags().StringVar(&mapOutput, "output", "", "Write graph to file")
	mapCmd.Flags().StringVar(&mapFormat, "format", "dot", "Output format: dot, mermaid")
	mapCmd.Flags().StringVar(&mapBlastFrom, "blast-from", "", "Calculate blast radius from this identity")
}
