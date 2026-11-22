// Run against debug binaries with `node browser/tests/e2e/remote-agent.mjs`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { runInNewContext } from "node:vm";

const root = await mkdtemp(join(homedir(), "rbw-browser-test-"));
const bin = resolve("target/debug");
const env = {
  ...process.env,
  PATH: `${bin}:${process.env.PATH}`,
  RBW_PROFILE: "signed-browser-test",
  XDG_CONFIG_HOME: join(root, "config"),
  XDG_CACHE_HOME: join(root, "cache"),
  XDG_DATA_HOME: join(root, "data"),
  XDG_RUNTIME_DIR: join(root, "runtime"),
};
const cli = (...args) => execFileSync(join(bin, "rbw"), args, { env, encoding: "utf8" });

function terminalCli(args, { color = true } = {}) {
  const terminalEnv = { ...env };
  if (color) delete terminalEnv.NO_COLOR;
  else terminalEnv.NO_COLOR = "1";
  return execFileSync("python3", ["-c", `
import errno, os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
while True:
    try:
        data = os.read(fd, 8192)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not data:
        break
    sys.stdout.buffer.write(data)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
`, join(bin, "rbw"), ...args], { env: terminalEnv, encoding: "utf8" });
}

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}

// Browser storage is isolated per simulated extension profile. Use Web
// Crypto for real key generation and signatures, and the real agent/CLI.
function browser(source, origin, port) {
  const records = new Map();
  const stored = {};
  const database = {
    close() {},
    transaction() {
      const tx = {
        objectStore: () => ({
          get(key) {
            const read = { result: records.get(key) };
            queueMicrotask(() => read.onsuccess());
            return read;
          },
          add(value, key) {
            records.set(key, value);
            queueMicrotask(() => tx.oncomplete());
          },
        }),
      };
      return tx;
    },
  };
  return runInNewContext(`${source}\nremoteAgent;`, {
    AbortSignal, TextEncoder, URL, Uint8Array, btoa, crypto,
    chrome: { storage: { local: {
      get: async key => ({ [key]: stored[key] }),
      set: async values => Object.assign(stored, values),
    } } },
    indexedDB: {
      open() {
        const request = { result: database };
        queueMicrotask(() => request.onsuccess());
        return request;
      },
    },
    async fetch(url, options) {
      assert.equal(new URL(url).origin, origin);
      assert.equal(options.redirect, "error");
      // Exercise the loopback upstream. The production proxy handles TLS.
      return fetch(`http://127.0.0.1:${port}${new URL(url).pathname}`, options);
    },
  });
}

try {
  const configDir = join(env.XDG_CONFIG_HOME, "rbw-signed-browser-test");
  await mkdir(configDir, { recursive: true });
  await mkdir(env.XDG_RUNTIME_DIR, { recursive: true, mode: 0o700 });
  const port = await freePort();
  const origin = "https://rbw.example.net";
  await writeFile(join(configDir, "config.yaml"), JSON.stringify({
    accounts: [{ name: "test", email: "browser@example.net" }],
    api: { listen: `127.0.0.1:${await freePort()}`, browser: { origin, port } },
  }));
  cli("api", "enable");
  const certificate = cli("api", "client", "create", "browser-daemon")
    .match(/Created client browser-daemon \(([a-f0-9]+)\)/)[1];
  cli("api", "grant", certificate, "--account", "test", "--item-id", "@all", "--field", "username");
  cli("api", "status-grant", certificate, "--account", "test");
  const directRow = cli("api", "policy", "list").split("\n").find(row => row.startsWith("direct\t"));
  const [, directGrants, directClient] = directRow.split("\t");
  assert.equal(directClient, certificate);
  assert.deepEqual(JSON.parse(directGrants), {
    name: "browser-daemon", account: "test", allItems: ["username"],
    items: {}, statusAccounts: ["test"], unlockAccounts: [],
  });
  assert.match(terminalCli(["api", "policy", "list"], { color: false }),
    /direct \(browser-daemon\) +[a-f0-9]+ +account test · all items: username · status: test/);
  const source = await readFile(new URL("../../extension/remote-agent.js", import.meta.url), "utf8");
  const extension = browser(source, origin, port);
  await assert.rejects(extension.configure("remote", "http://rbw.example.net"));
  await extension.configure("remote", origin);
  const pairing = await extension.pair(origin, "Test browser");
  const pairingTsv = cli("api", "pairing", "list");
  assert.ok(pairingTsv.includes(`${pairing.id}\t${pairing.code}\tpending`));
  const escape = String.fromCharCode(27);
  assert.ok(!pairingTsv.includes(escape));
  const pairingTable = terminalCli(["api", "pairing", "list"]);
  assert.match(pairingTable, /REQUEST ID/);
  assert.ok(pairingTable.split(escape).some(part => /^\[[0-9;]+mpending$/.test(part)));
  await assert.rejects(extension.call(origin, { action: "status" }));
  cli("api", "pairing", "approve", pairing.id, "--account", "test", "--policy", "read-only");
  assert.equal((await extension.send(origin, "pairing_status")).state, "approved");
  const clientTable = terminalCli(["api", "client", "list"], { color: false });
  assert.match(clientTable, /^NAME +CLIENT ID +AUTH +ACCOUNT +POLICY +GRANTS/m);
  assert.match(clientTable, /Test browser +[A-Za-z0-9_-]+ +browser +test +read-only/);
  assert.ok(!clientTable.includes(escape));
  assert.match(terminalCli(["api", "policy", "list"], { color: false }), /^POLICY +CLIENT ID +CAPABILITIES/m);
  assert.match(terminalCli(["api", "status"], { color: false }), /^FIELD +VALUE/m);
  assert.equal((await extension.call(origin, { action: "status" })).canUnlock, false);
  cli("api", "policy", "assign", pairing.id, "admin");
  assert.equal((await extension.call(origin, { action: "status" })).canUnlock, true);
  cli("api", "client", "revoke", pairing.id);
  await assert.rejects(extension.call(origin, { action: "status" }));

  const other = browser(source, origin, port);
  const denied = await other.pair(origin, "Other profile");
  assert.notEqual(denied.id, pairing.id);
  cli("api", "pairing", "deny", denied.id);
  assert.equal((await other.send(origin, "pairing_status")).state, "denied");
  assert.throws(() => cli("api", "pairing", "approve", denied.id, "--account", "test", "--policy", "admin"));
  console.log("Browser pairing, denial, shared policy reassignment and revocation passed.");
} finally {
  try { cli("stop-agent"); } catch { /* Setup may have failed before starting. */ }
  await rm(root, { recursive: true, force: true });
}
