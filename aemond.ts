import { spawn } from "child_process";
import { createDecipheriv, createHash } from "crypto";
import { readFileSync, existsSync, rmSync } from "fs";
import { resolve, dirname } from "path";
import { connect } from "node:net";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const PORT = 9070;
const CRED_KEY = process.env.AEMOND_CRED_KEY;

if (!CRED_KEY) {
  console.warn("\n⚠️  WARNING: AEMOND_CRED_KEY environment variable is not set!");
  console.warn("⚠️  Decryption of secure WebDoMa links will fail.");
  console.warn("⚠️  Please set AEMOND_CRED_KEY to the shared secret from your server's .env\n");
}

const ALGORITHM = "aes-256-gcm";
const TAG_LENGTH = 16;

// ---------- Syncplay configuration ----------
interface SyncplayConfig {
  host: string;
  room: string;
  user: string;
  pass?: string;
}

function loadSyncplayConfig(): SyncplayConfig | null {
  // Look for syncplay.conf next to this script
  const scriptDir = typeof __dirname !== "undefined"
    ? __dirname
    : dirname(fileURLToPath(import.meta.url));

  const confPath = resolve(scriptDir, "syncplay.conf");
  if (!existsSync(confPath)) {
    console.warn(`⚠️  syncplay.conf not found at ${confPath} — Syncplay endpoint will fail.`);
    return null;
  }

  const raw = readFileSync(confPath, "utf8");
  const map: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    map[trimmed.slice(0, eqIdx).trim()] = trimmed.slice(eqIdx + 1).trim();
  }

  const host = map.SYNCPLAY_HOST;
  const room = map.SYNCPLAY_ROOM;
  const user = map.SYNCPLAY_USER;
  if (!host || !room || !user) {
    console.warn("⚠️  syncplay.conf is missing required keys (SYNCPLAY_HOST, SYNCPLAY_ROOM, SYNCPLAY_USER)");
    return null;
  }

  return { host, room, user, pass: map.SYNCPLAY_PASS || undefined };
}

let syncplayConfig = loadSyncplayConfig();
if (syncplayConfig) {
  console.log(`✅ Syncplay config loaded — host=${syncplayConfig.host}, room=${syncplayConfig.room}, user=${syncplayConfig.user}`);
}

function deriveAemondKey(): Buffer {
  if (!CRED_KEY) throw new Error("AEMOND_CRED_KEY is missing on client");
  return createHash("sha256").update(CRED_KEY).digest();
}

function decryptAemondPayload(ciphertext: string): string {
  const parts = ciphertext.split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid cipher format (expected iv:tag:ct)");
  }

  const [ivHex, tagHex, ctHex] = parts;
  const key = deriveAemondKey();
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(tagHex, "hex");
  const ct = Buffer.from(ctHex, "hex");

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

interface PlayRequest {
  player: string;
  url?: string;
  cipher?: string;
  startTime?: string;
  torrent_id?: number;
  file_id?: number;
  account_id?: number;
  token?: string;
  reportUrl?: string;
}

// Converts "HH:MM:SS" / "MM:SS" / "SS" -> total seconds
function timeToSeconds(time: string): number {
  const parts = time.split(":").map(Number);
  if (parts.some((n) => Number.isNaN(n))) return 0;
  return parts.reduce((acc, n) => acc * 60 + n, 0);
}

function extractFilename(url: string): string {
  try {
    const u = new URL(url);
    const pathname = u.pathname;
    const filename = pathname.split("/").pop() || "stream";
    return filename.length > 80 ? filename.slice(0, 80) + "..." : filename;
  } catch {
    return "stream";
  }
}

// Command builders per player. Add more entries here to support other players.
// Each builder returns the executable to spawn + its argv.
const players: Record<
  string,
  (url: string, startTime: string, opts?: { socketPath?: string }) => { cmd: string; args: string[] }
> = {
  mpv: (url, startTime, opts) => ({
    cmd: "mpv",
    args: opts?.socketPath
      ? [url, `--start=${startTime}`, `--input-ipc-server=${opts.socketPath}`]
      : [url, `--start=${startTime}`],
  }),
  vlc: (url, startTime) => ({
    cmd: process.platform === "darwin" ? "/Applications/VLC.app/Contents/MacOS/vlc" : "vlc",
    args: [url, `--start-time=${timeToSeconds(startTime)}`],
  }),
  iina: (url, startTime) => ({
    // IINA's CLI tool (installed separately: `brew install --cask iina-cli` or via IINA app menu)
    cmd: "iina",
    args: [url, `--mpv-start=${startTime}`],
  }),
};

function resolveCommand(player: string, url: string, startTime: string, opts?: { socketPath?: string }) {
  const builder = players[player.toLowerCase()];
  if (builder) return builder(url, startTime, opts);
  // Unknown player name: treat it as the literal executable and just pass the url.
  return { cmd: player, args: [url] };
}

// ---------- mpv resume monitoring ----------

interface MpvMonitorOptions {
  reportUrl: string;
  token: string;
}

// mpv creates the IPC socket itself; the daemon connects as a client.
// Windows uses named pipes (no /tmp), posix uses a socket file.
function buildMpvSocketPath(torrentId?: number, fileId?: number): string {
  const rand = Math.random().toString(36).slice(2, 8);
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\mpv_relay_${torrentId ?? "x"}_${fileId ?? "x"}_${rand}`;
  }
  return resolve(tmpdir(), `mpv_relay_${torrentId ?? "x"}_${fileId ?? "x"}_${rand}.sock`);
}

// Listens for mpv property-change / end-file events over the IPC socket and
// reports playback position back to the server. Fire-and-forget; failures are
// logged and never crash the daemon.
function monitorMpv(socketPath: string, opts: MpvMonitorOptions) {
  let client: ReturnType<typeof connect> | null = null;
  let buffer = "";
  let lastPos = 0;
  let lastDuration: number | null = null;
  let lastReported = 0;
  let playing = true;
  let connected = false;
  let reportInterval: ReturnType<typeof setInterval> | null = null;
  let finished = false;

  const report = (position: number, duration: number | null, completed: boolean) => {
    if (finished) return;
    lastReported = position;
    fetch(opts.reportUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: opts.token,
        position: Math.max(0, position),
        duration: duration ?? null,
        completed,
      }),
    }).catch(() => {});
  };

  const teardown = () => {
    if (finished) return;
    finished = true;
    if (reportInterval) {
      clearInterval(reportInterval);
      reportInterval = null;
    }
    if (client) {
      try { client.destroy(); } catch { /* ignore */ }
    }
    if (process.platform !== "win32") {
      try { rmSync(socketPath, { force: true }); } catch { /* ignore */ }
    }
  };

  const handleMessage = (msg: any) => {
    if (msg.event === "property-change") {
      if (msg.id === 1 && typeof msg.data === "number") {
        // time-pos fires many times/sec — just cache it (debounced via interval)
        lastPos = msg.data;
      } else if (msg.id === 2 && typeof msg.data === "boolean") {
        playing = !msg.data;
        if (msg.data === true) report(lastPos, lastDuration, false);
      } else if (msg.id === 3 && typeof msg.data === "number") {
        lastDuration = msg.data;
      }
    } else if (msg.event === "end-file") {
      if (msg.reason === "eof") {
        report(lastDuration ?? lastPos, lastDuration, true);
      } else {
        // quit / stop / redirect / error / unknown — keep last known position
        report(lastPos, lastDuration, false);
      }
      teardown();
    }
  };

  const attemptConnect = (attempt = 0) => {
    if (finished) return;
    const sock = connect(socketPath);
    client = sock;
    sock.setEncoding("utf8");

    sock.on("connect", () => {
      connected = true;
      sock.write('{"command":["observe_property", 1, "time-pos"]}\n');
      sock.write('{"command":["observe_property", 2, "pause"]}\n');
      sock.write('{"command":["observe_property", 3, "duration"]}\n');
      // Periodic checkpoint every 15s (covers crash/kill/machine sleep)
      reportInterval = setInterval(() => {
        if (playing && Math.abs(lastPos - lastReported) >= 5) {
          report(lastPos, lastDuration, false);
        }
      }, 15000);
    });

    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try {
          handleMessage(JSON.parse(line));
        } catch {
          // ignore malformed lines
        }
      }
    });

    sock.on("error", (err) => {
      if (finished) return;
      // mpv creates the socket shortly after spawn — retry until it exists.
      if (!connected) {
        const code = (err as NodeJS.ErrnoException).code;
        if ((code === "ENOENT" || code === "ECONNREFUSED" || code === "EPIPE") && attempt < 30) {
          setTimeout(() => attemptConnect(attempt + 1), 100);
          return;
        }
      }
      console.error(`[${new Date().toISOString()}] mpv IPC error:`, err.message);
    });

    sock.on("close", () => {
      connected = false;
      if (reportInterval) {
        clearInterval(reportInterval);
        reportInterval = null;
      }
    });
  };

  attemptConnect();
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    if (url.pathname === "/health" && req.method === "GET") {
      return json({ status: "ok" });
    }

    if (url.pathname === "/play" && req.method === "POST") {
      let body: PlayRequest;
      try {
        body = await req.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const { player, url: requestUrl, cipher, startTime = "00:00", torrent_id, file_id, reportUrl, token } = body;

      if (!player) {
        return json({ error: "Missing required field: 'player'" }, 400);
      }

      let videoUrl: string;

      try {
        if (cipher) {
          videoUrl = decryptAemondPayload(cipher);
        } else if (requestUrl) {
          videoUrl = requestUrl;
        } else {
          return json({ error: "Missing required field: either 'cipher' or 'url'" }, 400);
        }
      } catch (err: any) {
        return json({ error: `Decryption failed: ${err.message}` }, 401);
      }

      // mpv only: enable IPC + progress reporting when the caller supplied a
      // reportUrl and token. Backward-compatible — old callers skip this.
      const socketPath =
        (player || "").toLowerCase() === "mpv" && reportUrl && token
          ? buildMpvSocketPath(torrent_id, file_id)
          : undefined;

      if (socketPath && process.platform !== "win32") {
        // Remove a stale socket file left over from a previous run
        try { rmSync(socketPath, { force: true }); } catch { /* ignore */ }
      }

      const { cmd, args } = resolveCommand(player, videoUrl, startTime, socketPath ? { socketPath } : undefined);

      try {
        const proc = spawn(cmd, args, {
          detached: true,

        });
        proc.unref(); // let it run independently of this daemon
        proc.on("error", (err) => {
          console.error(`[${new Date().toISOString()}] Spawn error for "${cmd}":`, err.message);
        });

        if (socketPath && reportUrl && token) {
          monitorMpv(socketPath, { reportUrl, token });
        }

        const displayUrl = args[0] ? extractFilename(args[0]) : "unknown";
        console.log(`[${new Date().toISOString()}] Launched: ${cmd} "${displayUrl}" (start: ${startTime})`);

        return json({ status: "launched", player });
      } catch (err) {
        console.error("Failed to spawn player:", err);
        return json({ error: `Failed to launch player: ${(err as Error).message}` }, 500);
      }
    }

    // ---------- Syncplay endpoint ----------
    if (url.pathname === "/syncplay" && req.method === "POST") {
      let body: PlayRequest;
      try {
        body = await req.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const { player, cipher, url: requestUrl } = body;

      if (!player) {
        return json({ error: "Missing required field: 'player'" }, 400);
      }

      // Re-read config on each request so users can hot-edit syncplay.conf
      syncplayConfig = loadSyncplayConfig();
      if (!syncplayConfig) {
        return json({ error: "Syncplay is not configured. Create syncplay.conf next to aemond.ts" }, 500);
      }

      let videoUrl: string;
      try {
        if (cipher) {
          videoUrl = decryptAemondPayload(cipher);
        } else if (requestUrl) {
          videoUrl = requestUrl;
        } else {
          return json({ error: "Missing required field: either 'cipher' or 'url'" }, 400);
        }
      } catch (err: any) {
        return json({ error: `Decryption failed: ${err.message}` }, 401);
      }

      // Resolve the player executable path
      const playerBuilder = players[player.toLowerCase()];
      const playerCmd = playerBuilder ? playerBuilder("", "").cmd : player;

      // Build syncplay CLI args
      const syncArgs: string[] = [
        "--host", syncplayConfig.host,
        "--room", syncplayConfig.room,
        "--name", syncplayConfig.user,
        "--player-path", playerCmd,
      ];
      if (syncplayConfig.pass) {
        syncArgs.push("--password", syncplayConfig.pass);
      }
      syncArgs.push(videoUrl);

      try {
        const syncplayCmd = process.platform === "darwin" ? "/Applications/Syncplay.app/Contents/MacOS/Syncplay" : "syncplay";
        const proc = spawn(syncplayCmd, syncArgs, {
          detached: true,
        });
        proc.unref();
        proc.on("error", (err) => {
          console.error(`[${new Date().toISOString()}] Syncplay spawn error:`, err.message);
        });

        const displayUrl = extractFilename(videoUrl);
        console.log(`[${new Date().toISOString()}] Syncplay: ${playerCmd} → room "${syncplayConfig.room}" "${displayUrl}"`);

        // SECURITY: Never return args or the decrypted URL
        return json({ status: "launched", player, room: syncplayConfig.room });
      } catch (err) {
        console.error("Failed to spawn syncplay:", err);
        return json({ error: `Failed to launch syncplay: ${(err as Error).message}` }, 500);
      }
    }

    return json({ error: "Not found" }, 404);
  },
});

console.log(`🎬 Player daemon running at http://localhost:${PORT}`);
console.log(`   POST http://localhost:${PORT}/play      { player, cipher | url, startTime? }`);
console.log(`   POST http://localhost:${PORT}/syncplay   { player, cipher | url }`);
console.log(`   GET  http://localhost:${PORT}/health`);
