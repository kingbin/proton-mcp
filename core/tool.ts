import { z, type ZodType } from "zod";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { GuardError } from "./guards.js";

/** Annotations for tools that only read (mail is never changed; nothing outside Bridge is contacted). */
export const READ_ANNOTATIONS: ToolAnnotations = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

/** Annotations for the save tool: it creates a new local file, never overwrites, never touches mail. */
export const SAVE_ANNOTATIONS: ToolAnnotations = Object.freeze({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
});

export interface ServerTool {
  name: string;
  description: string;
  annotations: ToolAnnotations;
  inputSchema: Record<string, unknown>;
  _zodSchema: ZodType;
  /** Takes RAW (unvalidated) args. Validates with the zod schema, then runs the handler. Never throws. */
  fn: (input: unknown) => Promise<CallToolResult>;
}

export function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

/**
 * Define a tool. The returned `fn` parses its own input (zod failure -> `INVALID_INPUT: ...`),
 * maps GuardError to `<CODE>: <message>`, and turns any other throw into `ERROR: <message>`.
 */
export function tool<S extends ZodType>(
  options: { name: string; description: string; inputSchema: S; annotations: ToolAnnotations },
  handler: (input: z.infer<S>) => Promise<CallToolResult>,
): ServerTool {
  return {
    name: options.name,
    description: options.description,
    annotations: { ...options.annotations },
    inputSchema: z.toJSONSchema(options.inputSchema, { io: "input" }) as Record<string, unknown>,
    _zodSchema: options.inputSchema,
    fn: async (raw: unknown) => {
      const parsed = options.inputSchema.safeParse(raw ?? {});
      if (!parsed.success) {
        const msg = parsed.error.issues
          .map((i) => `${i.path.join(".") || "input"}: ${i.message}`)
          .join("; ");
        return errorResult(`INVALID_INPUT: ${msg}`);
      }
      try {
        return await handler(parsed.data);
      } catch (e) {
        if (e instanceof GuardError) return errorResult(`${e.code}: ${e.message}`);
        return errorResult(`ERROR: ${e instanceof Error ? e.message : "unexpected failure"}`);
      }
    },
  };
}
