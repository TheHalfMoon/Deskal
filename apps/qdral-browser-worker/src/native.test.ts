// SG-000108 native confinement probes against the installed Edge.
//
// These run the real engine with the exact confinement argv (the shape that
// crates/qdral-browser-host/src/confinement.rs builds and that launchRefusal
// accepts). Layers 1 (resolver pinning) and 2 (no-route proxy) are probed
// with no policy route at all, as the decision record requires. On Windows a
// missing engine fails the suite; elsewhere the suite is skipped because only
// Windows results count as evidence. Fixtures are owned local servers.

import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createSocket } from "node:dgram";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createTcpServer, connect, type Server as TcpServer } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium, type BrowserContext } from "playwright-core";
import { encodeFrame, FrameDecoder, launchRefusal, type HostFrame, type WorkerFrame } from "./protocol.js";

const EDGE_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const isWindows = process.platform === "win32";
const engine = EDGE_CANDIDATES.find((path) => existsSync(path));
const skip = isWindows ? false : "native probes are Windows-only evidence";
const WORKER_MAIN = join(dirname(fileURLToPath(import.meta.url)), "main.js");
const FIXTURE_PORT = 443;

const FROZEN = [
  "--headless",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-extensions",
  "--disable-background-networking",
  "--disable-sync",
  "--no-service-autorun"
];

interface Destination {
  host: string;
  pin: string;
}

/// The confinement argv, built exactly as confinement.rs builds it.
function confinedArgv(profile: string, destinations: Destination[]): string[] {
  const rules = destinations
    .map(({ host, pin }) => `MAP ${host} ${pin.includes(":") ? `[${pin}]` : pin}:${FIXTURE_PORT}`)
    .concat("MAP * ~NOTFOUND")
    .join(", ");
  const bypass = [...destinations.map((d) => d.host), "<-loopback>"].join(";");
  return [
    ...FROZEN,
    `--user-data-dir=${profile}`,
    "--remote-debugging-pipe",
    `--host-resolver-rules=${rules}`,
    "--proxy-server=http://0.0.0.0:9",
    `--proxy-bypass-list=${bypass}`,
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-quic",
    "about:blank"
  ];
}

function requireEngine(): string {
  assert.ok(engine, `no Edge engine found at ${EDGE_CANDIDATES.join(" or ")}`);
  return engine;
}

function cleanEnv(): { SystemRoot: string; SystemDrive: string; PATH: string; TEMP: string; TMP: string } {
  const root = process.env.SystemRoot ?? "C:\\Windows";
  return {
    SystemRoot: root,
    SystemDrive: process.env.SystemDrive ?? "C:",
    PATH: `${root}\\System32`,
    TEMP: process.env.TEMP ?? `${root}\\Temp`,
    TMP: process.env.TMP ?? `${root}\\Temp`
  };
}

function launchFrame(profile: string, destinations: Destination[]): Extract<HostFrame, { frame: "launch" }> {
  const env = cleanEnv();
  const frame = {
    frame: "launch" as const,
    engine: requireEngine(),
    profile_dir: profile,
    argv: confinedArgv(profile, destinations),
    env: { SystemRoot: env.SystemRoot, PATH: env.PATH, TEMP: env.TEMP }
  };
  assert.equal(launchRefusal(frame), null, "the probe argv must satisfy the worker contract");
  return frame;
}

/// Windows command-line splitting (CommandLineToArgvW rules for arguments
/// after the program name; the program name is taken up to its closing quote).
function splitWindowsCommandLine(line: string): string[] {
  const args: string[] = [];
  let i = 0;
  if (line.startsWith('"')) {
    const end = line.indexOf('"', 1);
    args.push(line.slice(1, end));
    i = end + 1;
  } else {
    const end = line.search(/[ \t]/);
    args.push(end === -1 ? line : line.slice(0, end));
    i = end === -1 ? line.length : end;
  }
  while (i < line.length) {
    while (line[i] === " " || line[i] === "\t") i++;
    if (i >= line.length) break;
    let arg = "";
    let quoted = false;
    for (; i < line.length; i++) {
      const ch = line[i];
      if (ch === "\\") {
        let slashes = 0;
        while (line[i] === "\\") {
          slashes++;
          i++;
        }
        if (line[i] === '"') {
          arg += "\\".repeat(Math.floor(slashes / 2));
          if (slashes % 2 === 1) arg += '"';
          else quoted = !quoted;
        } else {
          arg += "\\".repeat(slashes);
          i--;
        }
      } else if (ch === '"') {
        if (quoted && line[i + 1] === '"') {
          arg += '"';
          i++;
        } else {
          quoted = !quoted;
        }
      } else if ((ch === " " || ch === "\t") && !quoted) {
        break;
      } else {
        arg += ch;
      }
    }
    args.push(arg);
  }
  return args;
}

/// Command lines of engine processes that use `profile`.
function engineCommandLines(profile: string): string[] {
  const leaf = profile.split("\\").pop() ?? profile;
  const out = execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*${leaf}*' } | ForEach-Object { $_.CommandLine }`
    ],
    { encoding: "utf8" }
  );
  return out.split(/\r?\n/).filter((line) => line.trim().length > 0);
}

async function waitFor(condition: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return condition();
}

class WorkerProcess {
  readonly child: ChildProcess;
  readonly replies: WorkerFrame[] = [];
  private readonly decoder = new FrameDecoder();
  private waiters: Array<() => void> = [];
  readonly exited: Promise<number | null>;

  constructor(nodeFlags: string[] = ["--disable-sigusr1"]) {
    this.child = spawn(process.execPath, [...nodeFlags, WORKER_MAIN], { env: cleanEnv(), stdio: ["pipe", "pipe", "pipe"] });
    this.child.stdout?.on("data", (chunk: Buffer) => {
      for (const frame of this.decoder.push(chunk)) this.replies.push(frame as WorkerFrame);
      for (const waiter of this.waiters.splice(0)) waiter();
    });
    this.child.stderr?.resume();
    this.exited = new Promise((resolve) => this.child.on("exit", (code) => resolve(code)));
  }

  send(frame: HostFrame): void {
    this.child.stdin?.write(encodeFrame(frame));
  }

  async reply(count: number, timeoutMs = 45_000): Promise<WorkerFrame> {
    const deadline = Date.now() + timeoutMs;
    while (this.replies.length < count) {
      assert.ok(Date.now() < deadline, `timed out waiting for reply ${count}: ${JSON.stringify(this.replies)}`);
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve);
        setTimeout(resolve, 500);
      });
    }
    return this.replies[count - 1] as WorkerFrame;
  }
}

function listen(server: Server | TcpServer, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host, ipv6Only: host === "::" }, () => resolve());
  });
}

test("the worker drives the installed engine with exactly the host argv and leaves nothing behind", { skip }, async () => {
  const profile = mkdtempSync(join(tmpdir(), "sg108-native-"));
  const worker = new WorkerProcess();
  try {
    worker.send({ frame: "hello", generation: 1 });
    assert.deepEqual(await worker.reply(1), { frame: "hello", generation: 1, worker: "qdral-browser-worker" });
    const launch = launchFrame(profile, [{ host: "fixture.test", pin: "127.0.0.1" }]);
    worker.send(launch);
    assert.deepEqual(await worker.reply(2), { frame: "launched" });

    const lines = engineCommandLines(profile);
    const browsers = lines.filter((line) => !line.includes("--type="));
    assert.equal(browsers.length, 1, `exactly one browser process: ${JSON.stringify(browsers)}`);
    assert.deepEqual(splitWindowsCommandLine(browsers[0] ?? ""), [launch.engine, ...launch.argv]);
    for (const line of lines) {
      for (const forbidden of ["--remote-debugging-port", "--remote-debugging-address", "--enable-automation"]) {
        assert.equal(line.includes(forbidden), false, `${forbidden} in ${line}`);
      }
    }
    worker.send({ frame: "ping", nonce: "native" });
    assert.deepEqual(await worker.reply(3), { frame: "pong", nonce: "native" });
    worker.send({ frame: "shutdown" });
    assert.deepEqual(await worker.reply(4), { frame: "bye" });
    assert.equal(await worker.exited, 0);
    assert.ok(await waitFor(() => engineCommandLines(profile).length === 0, 10_000), "engine processes remain after shutdown");
  } finally {
    worker.child.kill();
    rmSync(profile, { recursive: true, force: true });
  }
});

test("killing the worker takes the engine down with its pipe", { skip }, async () => {
  const profile = mkdtempSync(join(tmpdir(), "sg108-native-kill-"));
  const worker = new WorkerProcess();
  try {
    worker.send({ frame: "hello", generation: 1 });
    await worker.reply(1);
    worker.send(launchFrame(profile, [{ host: "fixture.test", pin: "127.0.0.1" }]));
    assert.deepEqual(await worker.reply(2), { frame: "launched" });
    assert.ok(engineCommandLines(profile).length > 0);
    worker.child.kill("SIGKILL");
    await worker.exited;
    // The host's kill-on-close Job Object (slice 2b-ii) is the guarantee;
    // this proves the engine also exits on its own when the pipe closes.
    assert.ok(await waitFor(() => engineCommandLines(profile).length === 0, 15_000), "engine survived the worker");
  } finally {
    worker.child.kill();
    rmSync(profile, { recursive: true, force: true });
  }
});

test("resolver pinning and the no-route proxy confine traffic without any policy route", { skip }, async () => {
  const hits: string[] = [];
  const fixture = createHttpServer((request, response) => {
    hits.push(`${request.headers.host ?? ""}${request.url ?? ""}`);
    response.setHeader("content-type", "text/html");
    response.end("<p>fixture</p>");
  });
  await listen(fixture, FIXTURE_PORT, "127.0.0.1");
  const accepts: Record<string, number> = {};
  const traps: TcpServer[] = [];
  for (const host of ["0.0.0.0", "127.0.0.1", "::"]) {
    const trap = createTcpServer((socket) => {
      accepts[host] = (accepts[host] ?? 0) + 1;
      socket.destroy();
    });
    await listen(trap, 9, host);
    accepts[host] = 0;
    traps.push(trap);
  }
  const profile = mkdtempSync(join(tmpdir(), "sg108-native-net-"));
  let context: BrowserContext | undefined;
  try {
    const argv = confinedArgv(profile, [{ host: "fixture.test", pin: "127.0.0.1" }]);
    context = await chromium.launchPersistentContext(profile, {
      executablePath: requireEngine(),
      ignoreDefaultArgs: true,
      args: argv,
      env: cleanEnv(),
      headless: true,
      timeout: 30_000
    });
    const open = async (url: string): Promise<string> => {
      const page = await context!.newPage();
      try {
        const response = await page.goto(url, { timeout: 10_000, waitUntil: "commit" });
        return `ok ${response?.status() ?? 0}`;
      } catch (error) {
        return `fail ${String((error as Error).message).split("\n")[0]}`;
      } finally {
        await page.close();
      }
    };
    assert.match(await open("http://fixture.test/admitted"), /^ok 200/);
    // Another port of the admitted name lands on the pinned port.
    assert.match(await open("http://fixture.test:8080/other-port"), /^ok 200/);
    for (const url of [
      "http://unmapped.test/",
      "http://example.com/",
      "http://127.0.0.1/",
      `http://127.0.0.1:${FIXTURE_PORT}/literal`,
      "http://[::1]/",
      "http://10.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://[fd00:ec2::254]/"
    ]) {
      assert.match(await open(url), /^fail .*ERR_(PROXY_CONNECTION_FAILED|NAME_NOT_RESOLVED)/, url);
    }
    assert.deepEqual(accepts, { "0.0.0.0": 0, "127.0.0.1": 0, "::": 0 }, "nothing reached a port-9 listener");
    assert.deepEqual(
      hits.filter((hit) => !hit.endsWith("/favicon.ico")),
      ["fixture.test/admitted", "fixture.test:8080/other-port"]
    );
  } finally {
    await context?.close();
    fixture.close();
    for (const trap of traps) trap.close();
    rmSync(profile, { recursive: true, force: true });
  }
});

test("WebRTC sends no UDP and opens no TURN connection", { skip }, async () => {
  const udp = createSocket("udp4");
  let packets = 0;
  udp.on("message", () => packets++);
  await new Promise<void>((resolve) => udp.bind(0, "127.0.0.1", () => resolve()));
  const udpPort = (udp.address() as { port: number }).port;
  let turnConnections = 0;
  const fixture = createHttpServer((_request, response) => response.end("<p>fixture</p>"));
  fixture.on("connection", () => turnConnections++);
  await listen(fixture, FIXTURE_PORT, "127.0.0.1");
  const lan = Object.values(networkInterfaces())
    .flat()
    .find((address) => address && address.family === "IPv4" && !address.internal)?.address;
  const profile = mkdtempSync(join(tmpdir(), "sg108-native-rtc-"));
  let context: BrowserContext | undefined;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath: requireEngine(),
      ignoreDefaultArgs: true,
      args: confinedArgv(profile, [{ host: "fixture.test", pin: "127.0.0.1" }]),
      env: cleanEnv(),
      headless: true,
      timeout: 30_000
    });
    const page = await context.newPage();
    await page.goto("http://fixture.test/", { waitUntil: "commit" });
    const before = turnConnections;
    const servers = [`stun:127.0.0.1:${udpPort}`, `turn:127.0.0.1:${FIXTURE_PORT}?transport=tcp`];
    if (lan) servers.push(`stun:${lan}:${udpPort}`);
    const candidates = await page.evaluate(async (urls: string[]) => {
      const types: string[] = [];
      for (const url of urls) {
        const server = url.startsWith("turn:") ? { urls: url, username: "u", credential: "c" } : { urls: url };
        const connection = new RTCPeerConnection({ iceServers: [server] });
        connection.createDataChannel("probe");
        connection.onicecandidate = (event) => {
          if (event.candidate) types.push(event.candidate.type ?? "unknown");
        };
        await connection.setLocalDescription(await connection.createOffer());
        await new Promise((resolve) => setTimeout(resolve, 2500));
        connection.close();
      }
      return types;
    }, servers);
    assert.deepEqual(candidates, [], "no ICE candidate is gathered");
    assert.equal(packets, 0, "no UDP packet left the engine");
    assert.equal(turnConnections - before, 0, "no TURN-over-TCP connection was opened");
  } finally {
    await context?.close();
    udp.close();
    fixture.close();
    rmSync(profile, { recursive: true, force: true });
  }
});

test("a same-user process cannot activate the worker's inspector when it runs with --disable-sigusr1", { skip }, async () => {
  const listening = (port: number) =>
    new Promise<boolean>((resolve) => {
      const socket = connect({ host: "127.0.0.1", port }, () => {
        socket.destroy();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
    });
  const debugProcess = (process as unknown as { _debugProcess(pid: number): void })._debugProcess;
  const attempt = async (flags: string[]) => {
    const worker = new WorkerProcess(flags);
    await new Promise((resolve) => setTimeout(resolve, 750));
    const before = await listening(9229);
    let threw = false;
    try {
      debugProcess(worker.child.pid ?? 0);
    } catch {
      threw = true;
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const after = await listening(9229);
    worker.child.kill();
    await worker.exited;
    return { before, threw, after };
  };
  const guarded = await attempt(["--disable-sigusr1"]);
  assert.equal(guarded.before, false, "port 9229 must be free for the probe");
  assert.equal(guarded.threw, true, "activation must be refused");
  assert.equal(guarded.after, false, "no inspector listener may appear");
  // Negative control: without the flag the same activation opens a listener,
  // so the guarded result above is not an artifact of the probe.
  const control = await attempt([]);
  assert.equal(control.after, true, "the probe can detect an activated inspector");
});
