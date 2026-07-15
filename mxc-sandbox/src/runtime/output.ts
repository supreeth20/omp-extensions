type UnknownRecord = Record<string, unknown>;

type OutputEvent = {
  sequence: number;
  stream: "stdout" | "stderr";
  data: string | Uint8Array;
};

function bytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  return new TextEncoder().encode(String(value ?? ""));
}

function decode(chunks: readonly Uint8Array[]): string {
  if (chunks.length === 0) return "";
  const length = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}

function truncatePreview(raw: string, maxColumns: number, maxLines: number): { preview: string; truncated: boolean } {
  let truncated = false;
  const lines = raw.split("\n").map((line) => {
    if (line.length <= maxColumns) return line;
    truncated = true;
    return `${line.slice(0, Math.max(0, maxColumns - 1))}…`;
  });
  if (lines.length > maxLines) {
    truncated = true;
    const visibleLines = lines.at(-1) === "" ? lines.slice(0, -1) : lines;
    const available = Math.max(2, maxLines);
    const headCount = Math.ceil((available - 1) / 2);
    const tailCount = Math.floor((available - 1) / 2);
    const omitted = visibleLines.length - headCount - tailCount;
    const tail = tailCount > 0 ? visibleLines.slice(-tailCount) : [];
    return { preview: [...visibleLines.slice(0, headCount), `… ${omitted} lines omitted …`, ...tail].join("\n"), truncated };
  }
  return { preview: lines.join("\n"), truncated };
}

export async function renderMxcOutput(input: UnknownRecord): Promise<UnknownRecord> {
  const events = Array.isArray(input.events)
    ? (input.events as OutputEvent[]).slice().sort((left, right) => left.sequence - right.sequence)
    : [];
  const stdoutChunks: Uint8Array[] = [];
  const stderrChunks: Uint8Array[] = [];
  let rawChunks: Uint8Array[];
  if (events.length > 0) {
    rawChunks = events.map((event) => {
      const chunk = bytes(event.data);
      (event.stream === "stderr" ? stderrChunks : stdoutChunks).push(chunk);
      return chunk;
    });
  } else {
    rawChunks = Array.isArray(input.rawChunks) ? input.rawChunks.map(bytes) : [];
  }

  const raw = decode(rawChunks);
  const maxColumns = typeof input.maxColumns === "number" && input.maxColumns > 0 ? Math.floor(input.maxColumns) : 200;
  const maxLines = typeof input.maxLines === "number" && input.maxLines > 0 ? Math.floor(input.maxLines) : 200;
  const rendered = truncatePreview(raw, maxColumns, maxLines);

  let artifact = typeof input.artifact === "string" ? input.artifact : undefined;
  if (!artifact && rawChunks.length > 0 && typeof input.allocateArtifactPath === "function" && typeof input.writeArtifact === "function") {
    const allocation = await input.allocateArtifactPath();
    if (allocation && typeof allocation === "object") {
      const item = allocation as UnknownRecord;
      if (typeof item.id === "string" && typeof item.path === "string") {
        for (const chunk of rawChunks) await input.writeArtifact(item.path, chunk);
        artifact = `artifact://${item.id}`;
      }
    }
  }

  const exitCode = typeof input.exitCode === "number" ? input.exitCode : 0;
  const timedOut = input.timedOut === true;
  const cancelled = input.cancelled === true;
  const wallTimeMs = typeof input.wallTimeMs === "number" ? input.wallTimeMs : 0;
  return {
    preview: rendered.preview,
    truncated: rendered.truncated,
    ...(artifact ? { artifact } : {}),
    streams: {
      stdout: events.length > 0 ? decode(stdoutChunks) : raw,
      stderr: events.length > 0 ? decode(stderrChunks) : "",
    },
    details: { exitCode, timedOut, cancelled, wallTimeMs, truncated: rendered.truncated },
  };
}
