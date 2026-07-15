type UnknownRecord = Record<string, unknown>;

type ArtifactAllocation = { id: string; path: string };

export interface LosslessArtifactSink {
  readonly allocation: ArtifactAllocation;
  write(chunk: Uint8Array): void;
  close(): Promise<void>;
}

export async function createLosslessArtifactSink(sessionManager: UnknownRecord, kind: "bash" | "powershell"): Promise<LosslessArtifactSink> {
  if (typeof sessionManager.allocateArtifactPath !== "function") {
    throw Object.assign(new Error("OMP artifact allocation is required for lossless shell output"), { code: "ARTIFACT_ALLOCATION_REQUIRED" });
  }
  const raw = await sessionManager.allocateArtifactPath(kind);
  if (!raw || typeof raw !== "object") throw Object.assign(new Error("OMP returned an invalid artifact allocation"), { code: "ARTIFACT_ALLOCATION_FAILED" });
  const allocation = raw as UnknownRecord;
  if (typeof allocation.id !== "string" || typeof allocation.path !== "string") {
    throw Object.assign(new Error("OMP returned an invalid artifact allocation"), { code: "ARTIFACT_ALLOCATION_FAILED" });
  }
  const writer = Bun.file(allocation.path).writer();
  let closed = false;
  return {
    allocation: { id: allocation.id, path: allocation.path },
    write(chunk: Uint8Array): void {
      if (closed) throw Object.assign(new Error("Artifact sink is closed"), { code: "ARTIFACT_SINK_CLOSED" });
      writer.write(chunk);
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await writer.end();
    },
  };
}
