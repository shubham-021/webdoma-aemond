import { spawn } from "child_process";
import { createDecipheriv, createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
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
  (url: string, startTime: string) => { cmd: string; args: string[] }
> = {
  mpv: (url, startTime) => ({
    cmd: "mpv",
    args: [url, `--start=${startTime}`],
  }),
  vlc: (url, startTime) => ({
    cmd: process.platform === "darwin" ?  "/Application/VLC/Contents/MacOS/vlc" : "vlc",
    args: [url, `--start-time=${timeToSeconds(startTime)}`],
  }),
  iina: (url, startTime) => ({
    // IINA's CLI tool (installed separately: `brew install --cask iina-cli` or via IINA app menu)
    cmd: "iina",
    args: [url, `--mpv-start=${startTime}`],
  }),
};

function resolveCommand(player: string, url: string, startTime: string) {
  const builder = players[player.toLowerCase()];
  if (builder) return builder(url, startTime);
  // Unknown player name: treat it as the literal executable and just pass the url.
  return { cmd: player, args: [url] };
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

      const { player, url: requestUrl, cipher, startTime = "00:00" } = body;

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

      const { cmd, args } = resolveCommand(player, videoUrl, startTime);

      try {
        const proc = spawn(cmd, args, {
          detached: true,
          
        });
        proc.unref(); // let it run independently of this daemon
        proc.on("error", (err) => {
          console.error(`[${new Date().toISOString()}] Spawn error for "${cmd}":`, err.message);
        });

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

      const { player, cipher } = body;

      if (!player) {
        return json({ error: "Missing required field: 'player'" }, 400);
      }
      if (!cipher) {
        return json({ error: "Missing required field: 'cipher'" }, 400);
      }

      // Re-read config on each request so users can hot-edit syncplay.conf
      syncplayConfig = loadSyncplayConfig();
      if (!syncplayConfig) {
        return json({ error: "Syncplay is not configured. Create syncplay.conf next to aemond.ts" }, 500);
      }

      let videoUrl: string;
      try {
        videoUrl = decryptAemondPayload(cipher);
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
        const proc = spawn("syncplay", syncArgs, {
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
console.log(`   POST http://localhost:${PORT}/syncplay   { player, cipher }`);
console.log(`   GET  http://localhost:${PORT}/health`);
