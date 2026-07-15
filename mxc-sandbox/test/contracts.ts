import { expect } from "bun:test";

export type ContractModule = Record<string, unknown>;

const moduleUrls = {
  activation: new URL("../src/runtime/features.ts", import.meta.url).href,
  broker: new URL("../src/broker/permission-broker.ts", import.meta.url).href,
  commands: new URL("../src/commands/sandbox.ts", import.meta.url).href,
  environment: new URL("../src/policy/environment.ts", import.meta.url).href,
  e2e: new URL("../src/e2e/driver.ts", import.meta.url).href,
  execution: new URL("../src/runtime/process.ts", import.meta.url).href,
  extension: new URL("../index.ts", import.meta.url).href,
  filesystem: new URL("../src/policy/filesystem.ts", import.meta.url).href,
  jobs: new URL("../src/runtime/jobs.ts", import.meta.url).href,
  network: new URL("../src/policy/network.ts", import.meta.url).href,
  output: new URL("../src/runtime/output.ts", import.meta.url).href,
  paths: new URL("../src/policy/paths.ts", import.meta.url).href,
  profiles: new URL("../src/profiles/index.ts", import.meta.url).href,
  sdk: new URL("../src/mxc/sdk.ts", import.meta.url).href,
  probe: new URL("../src/mxc/probe.ts", import.meta.url).href,
  state: new URL("../src/state/index.ts", import.meta.url).href,
  tools: new URL("../src/integration/tool-gate.ts", import.meta.url).href,
  windows: new URL("../src/platform/windows.ts", import.meta.url).href,
  ui: new URL("../src/ui/index.ts", import.meta.url).href,
} as const;

export type ContractName = keyof typeof moduleUrls;

export async function loadContract(name: ContractName): Promise<ContractModule> {
  try {
    // This is an intentional module-loading-boundary test: production modules do not exist in RED.
    return (await import(moduleUrls[name])) as ContractModule;
  } catch (error) {
    throw new Error(`Missing production contract "${name}" at ${moduleUrls[name]}`, { cause: error });
  }
}

export function requiredExport<T>(module: ContractModule, name: string): T {
  expect(module).toHaveProperty(name);
  const value = module[name];
  expect(value).toBeDefined();
  return value as T;
}

export function expectFailureCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error(`Expected failure code ${code}`);
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}

export async function expectAsyncFailureCode(action: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await action();
    throw new Error(`Expected failure code ${code}`);
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}

export function uniqueValues(values: string[]): void {
  expect(new Set(values).size).toBe(values.length);
}
