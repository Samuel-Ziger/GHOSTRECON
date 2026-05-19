"use client";
import { Handle, Position, type NodeProps } from "reactflow";
import clsx from "clsx";

// Cor de heat: low -> mid -> high
function heatColor(h: number): string {
  if (h >= 0.66) return "border-heat-high text-heat-high";
  if (h >= 0.33) return "border-heat-mid  text-heat-mid";
  return "border-border text-mute";
}

// Glyph + classe por label
const LABEL_STYLE: Record<string, { dot: string; glyph: string }> = {
  Endpoint:         { dot: "bg-accent",  glyph: "EP" },
  Page:             { dot: "bg-accent2", glyph: "PG" },
  GraphQLOperation: { dot: "bg-pink-400", glyph: "GQ" },
  ApiOperation:     { dot: "bg-accent",  glyph: "API" },
  Param:            { dot: "bg-mute",    glyph: "P" },
  JWT:              { dot: "bg-warn",    glyph: "JWT" },
  Cookie:           { dot: "bg-warn",    glyph: "CK" },
  Role:             { dot: "bg-ok",      glyph: "R" },
  Host:             { dot: "bg-mute",    glyph: "H" },
  Upload:           { dot: "bg-warn",    glyph: "UP" },
  Bucket:           { dot: "bg-warn",    glyph: "B" },
  Integration:      { dot: "bg-accent2", glyph: "IN" },
};

export interface GhostNodeData {
  label: string;
  title: string;
  heat: number;
  props: Record<string, unknown>;
}

export function GhostNode({ data, selected }: NodeProps<GhostNodeData>) {
  const style = LABEL_STYLE[data.label] ?? { dot: "bg-mute", glyph: "?" };
  return (
    <div
      className={clsx(
        "rounded-lg border bg-panel shadow-node px-3 py-2 min-w-[150px] max-w-[260px]",
        "transition-all duration-150",
        selected ? "ring-1 ring-accent" : "",
        heatColor(data.heat),
      )}
    >
      <Handle type="target" position={Position.Left}  className="!bg-border" />
      <Handle type="source" position={Position.Right} className="!bg-border" />
      <div className="flex items-center gap-2 mb-1">
        <span className={clsx("inline-block h-2 w-2 rounded-full", style.dot)} />
        <span className="text-[10px] uppercase tracking-wider text-mute">{data.label}</span>
        {data.heat > 0 && (
          <span className="ml-auto text-[10px] tabular-nums">
            {(data.heat * 100).toFixed(0)}%
          </span>
        )}
      </div>
      <div className="text-sm text-ink truncate" title={data.title}>{data.title}</div>
    </div>
  );
}
