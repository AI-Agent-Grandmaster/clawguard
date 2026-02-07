/**
 * ClawGuard Intent Graph Generator
 *
 * Builds a visual graph of what a skill can:
 * - READ (data sources)
 * - WRITE (persistence targets)
 * - SEND (exfiltration channels)
 *
 * This makes the attack surface immediately visible.
 */
interface DataNode {
    id: string;
    type: 'source' | 'sink' | 'skill' | 'channel';
    label: string;
    risk: 'low' | 'medium' | 'high' | 'critical';
    category: string;
}
interface DataEdge {
    from: string;
    to: string;
    action: 'read' | 'write' | 'send' | 'exec';
    evidence: string;
}
interface IntentGraph {
    nodes: DataNode[];
    edges: DataEdge[];
    summary: {
        sensitiveReads: string[];
        exfilChannels: string[];
        persistenceTargets: string[];
        execCapabilities: boolean;
        riskAssessment: string;
    };
}
/**
 * Build an intent graph for a skill
 */
export declare function buildIntentGraph(skillPath: string): Promise<IntentGraph>;
/**
 * Render intent graph as ASCII art
 */
export declare function renderGraphAscii(graph: IntentGraph): string;
/**
 * Render intent graph as Mermaid diagram (for markdown)
 */
export declare function renderGraphMermaid(graph: IntentGraph): string;
export type { IntentGraph, DataNode, DataEdge };
