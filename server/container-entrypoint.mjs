// Apply packaged migrations before starting the API, without a shell or npm.
// Each child owns a process group so shutdown reaches Prisma's schema engine
// as well as the CLI. The parent waits for child exit and preserves its status.
import { spawn } from "node:child_process";
import { constants } from "node:os";
import { fileURLToPath } from "node:url";
import { normalizeDatabaseUrl } from "./database-url.mjs";

normalizeDatabaseUrl(process.env);

let child;
let stopping = false;
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    stopping = true;
    if (child?.pid) {
      try {
        process.kill(-child.pid, signal);
      } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    }
  });
}

const local = (path) => fileURLToPath(new URL(path, import.meta.url));
for (const args of [
  [local("./node_modules/prisma/build/index.js"), "migrate", "deploy", "--schema", local("./prisma/schema.prisma")],
  [local("./dist/index.js")],
]) {
  if (stopping) break;
  const result = await new Promise((resolve) => {
    child = spawn(process.execPath, args, { stdio: "inherit", detached: true });
    child.once("error", () => resolve({ code: 1 }));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child = undefined;
  const status = result.code ?? (128 + (constants.signals[result.signal] ?? 1));
  if (stopping || status !== 0) process.exit(status);
}
