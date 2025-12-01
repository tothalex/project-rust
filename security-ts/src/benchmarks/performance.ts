/**
 * Comprehensive performance benchmark for security-ts
 * Run with: pnpm tsx src/benchmarks/performance.ts
 */

import { VirtualDevice } from "../lib/virtual-device";
import { Hiver } from "../modules/hiver";
import type { IActorContract } from "../types/common";

// Memory tracking utility
function getMemoryUsage(): { rss: number; heapUsed: number; heapTotal: number } {
  const mem = process.memoryUsage();
  return {
    rss: mem.rss / 1024 / 1024, // MB
    heapUsed: mem.heapUsed / 1024 / 1024, // MB
    heapTotal: mem.heapTotal / 1024 / 1024, // MB
  };
}

function printMemory(label: string) {
  const mem = getMemoryUsage();
  console.log(
    `${label}: RSS=${mem.rss.toFixed(2)}MB, Heap=${mem.heapUsed.toFixed(2)}/${mem.heapTotal.toFixed(2)}MB`,
  );
}

// Create mock actor contract
function createMockActorContract(numMembers: number): IActorContract {
  const members = Array.from({ length: numMembers }, () => {
    const keys = Hiver.generateKeyPairHex();
    const id = Hiver.generateId().serializeToHexStr();
    return { id, pm: keys.publicKey };
  });

  const threshold = Math.ceil((numMembers + 1) / 2);

  return {
    id: "mock-contract-id",
    threshold,
    newMembers: members,
    contributions: [],
    actorShare: {
      shareCode: "MOCK_SHARE",
      subjectActorId: "mock-subject",
      hatId: "mock-hat",
      fromActorId: "mock-from",
      toActorId: "mock-to",
      ownerActorId: "mock-owner",
      subjectActorType: "DEVICE",
      roleCode: "DEVICEREG",
    },
  };
}

// Benchmark runner
function benchmark(
  name: string,
  iterations: number,
  fn: () => void,
): void {
  console.log(`\n--- Benchmarking ${name} ---`);
  printMemory("Before");

  const start = process.hrtime.bigint();

  for (let i = 0; i < iterations; i++) {
    fn();
  }

  const end = process.hrtime.bigint();
  const durationMs = Number(end - start) / 1_000_000;

  printMemory("After");

  console.log(`Total time for ${iterations} iterations: ${durationMs.toFixed(2)}ms`);
  console.log(`Average time per call: ${(durationMs / iterations).toFixed(3)}ms`);
  console.log(`Operations per second: ${((iterations / durationMs) * 1000).toFixed(2)}`);
}

async function main() {
  console.log("=== Security-TS Performance Benchmarks ===\n");

  // Initialize BLS
  await Hiver.init();
  console.log("BLS initialized\n");

  // Benchmark VirtualDevice creation
  benchmark("new VirtualDevice()", 1000, () => {
    new VirtualDevice("Benchmark Device");
  });

  // Benchmark contribution generation with different member counts
  for (const numMembers of [2, 3, 5, 10]) {
    const contract = createMockActorContract(numMembers);
    benchmark(
      `generateContribution with ${numMembers} members (threshold ${contract.threshold})`,
      100,
      () => {
        const device = new VirtualDevice("Benchmark Device");
        device.generateContribution(contract);
      },
    );
  }

  // Benchmark keypair generation
  benchmark("Hiver.generateKeyPairHex()", 10000, () => {
    Hiver.generateKeyPairHex();
  });

  // Benchmark ID generation
  benchmark("Hiver.generateId()", 10000, () => {
    Hiver.generateId();
  });

  console.log("\n=== Benchmarks Complete ===");
  console.log("\nFinal Memory Usage:");
  printMemory("Final");
}

main().catch(console.error);
