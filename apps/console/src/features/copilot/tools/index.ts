// Public surface of the copilot tool system. Re-exports the registry and
// engine so callers have a single import point.

export type { ExecuteToolOptions } from "./execution-engine";
export { executeTool } from "./execution-engine";
export { enabledTools, getTool, listTools } from "./tool-registry";
export type {
  ConfirmRequest,
  ExecutionStatus,
  ToolCategory,
  ToolContext,
  ToolDefinition,
  ToolExecution,
  ToolResult,
} from "./tool-types";
