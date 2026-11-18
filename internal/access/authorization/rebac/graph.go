package rebac

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// GraphNode is a vertex in a relationship graph (a "type:id" identity).
type GraphNode struct {
	ID    string `json:"id"`             // e.g. "document:readme"
	Type  string `json:"type"`           // e.g. "document"
	Label string `json:"label"`          // e.g. "readme"
	Name  string `json:"name,omitempty"` // a user node's person, when they belong to the organization
}

// GraphEdge is a directed relationship between two nodes.
type GraphEdge struct {
	From     string `json:"from"`     // "type:id"
	To       string `json:"to"`       // "type:id"
	Relation string `json:"relation"` // the named relation
}

// Graph is the result of an Expand call: all nodes and directed edges reachable
// from a root object+relation up to some depth. Suitable for graph rendering.
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// graphNodeID formats a GraphNode ID from type+id parts.
func graphNodeID(typ, id string) string { return typ + ":" + id }

// maxExpandDepth caps how many userset hops Expand follows.
const maxExpandDepth = 10

// expand returns the nodes and edges reachable from objType:objID#relation,
// following at most limit userset hops. It walks breadth first, so each
// object#relation is expanded once, at its fewest hops, and cycles end.
func expand(fetch fetcher, objType, objID, relation string, limit int) (map[string]GraphNode, []GraphEdge, error) {
	type step struct {
		typ, id, relation string
		depth             int
	}
	nodes := map[string]GraphNode{}
	edges := make([]GraphEdge, 0)
	addNode := func(typ, id string) string {
		nid := graphNodeID(typ, id)
		if _, ok := nodes[nid]; !ok {
			nodes[nid] = GraphNode{ID: nid, Type: typ, Label: id}
		}
		return nid
	}
	queue := []step{{objType, objID, relation, 0}}
	queued := map[string]bool{objType + ":" + objID + "#" + relation: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fromID := addNode(cur.typ, cur.id)
		tuples, err := fetch(cur.typ, cur.id, cur.relation)
		if err != nil {
			return nil, nil, err
		}
		for _, t := range tuples {
			toID := addNode(t.subjectType, t.subjectID)
			// A userset edge names both relations, so "viewer → member" reads
			// as "viewer via group#member".
			edgeRelation := cur.relation
			if t.subjectRelation != "" {
				edgeRelation = cur.relation + " → " + t.subjectRelation
			}
			edges = append(edges, GraphEdge{From: fromID, To: toID, Relation: edgeRelation})

			// "group:eng#member" also expands group:eng at its "member" relation.
			key := t.subjectType + ":" + t.subjectID + "#" + t.subjectRelation
			if t.subjectRelation != "" && cur.depth < limit && !queued[key] {
				queued[key] = true
				queue = append(queue, step{t.subjectType, t.subjectID, t.subjectRelation, cur.depth + 1})
			}
		}
	}
	return nodes, edges, nil
}

// Expand returns the graph of every subject reachable from object#relation
// ("who can reach this resource?"), following usersets up to depth hops
// (maxExpandDepth when depth is out of range). Each node appears once. It
// reads within one request budget: a wider graph is ErrReBACCheckTooComplex.
func (s *Service) Expand(ctx context.Context, organizationID uuid.UUID, object, relation string, depth int) (*Graph, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	if strings.TrimSpace(relation) == "" {
		return nil, ErrRelationRequired
	}
	if depth <= 0 || depth > maxExpandDepth {
		depth = maxExpandDepth
	}
	nodes, edges, err := expand(s.tupleFetcher(WithRequestBudget(ctx), organizationID), o.Type, o.ID, relation, depth)
	if err != nil {
		return nil, err
	}

	people := []string{}
	for _, n := range nodes {
		if n.Type == "user" {
			people = append(people, n.Label)
		}
	}
	names, err := s.namePeople(ctx, organizationID, people)
	if err != nil {
		return nil, err
	}
	nodeList := make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		if n.Type == "user" {
			n.Name = names[n.Label]
		}
		nodeList = append(nodeList, n)
	}
	return &Graph{Nodes: nodeList, Edges: edges}, nil
}
