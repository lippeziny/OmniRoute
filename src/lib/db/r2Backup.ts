import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveWritableDataDir } from "../dataPaths";

const MANIFEST_NAME = "latest.json";
const SLOT_COUNT = 3;
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "binary");
const TRUE_CLOUD_RUNTIME =
  typeof globalThis.caches === "object" && globalThis.caches !== null;

type R2Config = {
  endpoint: URL;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  prefix: string;
};

type BackupSnapshot = {
  slot: number;
  sha256: string;
  size: number;
  updatedAt: string;
};

type BackupManifest = {
  schema: "omniroute-r2-backup-v1";
  snapshots: BackupSnapshot[];
};

function envValue(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function getR2Config(): R2Config | null {
  const names = [
    "R2_ACCOUNT_ID",
    "R2_BUCKET",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
  ] as const;
  const values = names.map((name) => envValue(name));
  const anyConfigured = values.some(Boolean) || Boolean(envValue("R2_ENDPOINT"));
  if (!anyConfigured) return null;

  const missing = names.filter((_, index) => !values[index]);
  if (missing.length > 0) {
    throw new Error(
      `[R2] Incomplete configuration. Missing environment variables: ${missing.join(", ")}`
    );
  }

  const [accountId, bucket, accessKeyId, secretAccessKey] = values as [
    string,
    string,
    string,
    string,
  ];
  const endpointValue =
    envValue("R2_ENDPOINT") ?? `https://${accountId}.r2.cloudflarestorage.com`;

  let endpoint: URL;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    throw new Error("[R2] R2_ENDPOINT must be a valid HTTPS URL.");
  }
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    (endpoint.pathname !== "/" && endpoint.pathname !== "")
  ) {
    throw new Error(
      "[R2] R2_ENDPOINT must be the HTTPS account endpoint, without credentials, path, query, or fragment."
    );
  }

  const prefix = (envValue("R2_PREFIX") ?? "omniroute").replace(/^\/+|\/+$/g, "");
  if (!prefix || prefix.split("/").some((part) => part === "." || part === "..")) {
    throw new Error("[R2] R2_PREFIX is invalid.");
  }

  return { endpoint, bucket, accessKeyId, secretAccessKey, prefix };
}

function sha256(value: Buffer | string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmac(key: Buffer | string, value: string): Buffer {
  return crypto.createHmac("sha256", key).update(value, "utf8").digest();
}

function encodePathPart(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function objectUrl(config: R2Config, key: string): URL {
  const url = new URL(config.endpoint);
  const encodedKey = key.split("/").map(encodePathPart).join("/");
  url.pathname = `/${encodePathPart(config.bucket)}/${encodedKey}`;
  return url;
}

async function signedRequest(
  config: R2Config,
  method: "GET" | "PUT",
  key: string,
  body?: Buffer
): Promise<Response> {
  const url = objectUrl(config, key);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256(body ?? Buffer.alloc(0));
  const region = "auto";
  const service = "s3";
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalHeaders =
    `host:${url.host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;
  const canonicalRequest = [
    method,
    url.pathname,
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256(canonicalRequest),
  ].join("\n");

  const dateKey = hmac(`AWS4${config.secretAccessKey}`, dateStamp);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, service);
  const signingKey = hmac(serviceKey, "aws4_request");
  const signature = hmac(signingKey, stringToSign).toString("hex");
  const authorization =
    `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = await fetch(url, {
    method,
    headers: {
      authorization,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
    },
    body: body ? new Uint8Array(body) : undefined,
    signal: AbortSignal.timeout(120_000),
  });
  return response;
}

function manifestKey(config: R2Config): string {
  return `${config.prefix}/${MANIFEST_NAME}`;
}

function slotKey(config: R2Config, slot: number): string {
  return `${config.prefix}/storage-${slot}.sqlite`;
}

async function readManifest(config: R2Config): Promise<BackupManifest | null> {
  const response = await signedRequest(config, "GET", manifestKey(config));
  if (response.status === 404) return null;
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    throw new Error(`[R2] Could not read backup manifest (HTTP ${response.status}): ${detail}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await response.text());
  } catch {
    throw new Error("[R2] Backup manifest is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("[R2] Backup manifest has an invalid shape.");
  }

  const value = parsed as Partial<BackupManifest>;
  if (
    value.schema !== "omniroute-r2-backup-v1" ||
    !Array.isArray(value.snapshots) ||
    value.snapshots.length < 1 ||
    value.snapshots.length > SLOT_COUNT
  ) {
    throw new Error("[R2] Backup manifest failed validation.");
  }

  const seenSlots = new Set<number>();
  for (const snapshot of value.snapshots) {
    if (
      !snapshot ||
      !Number.isInteger(snapshot.slot) ||
      snapshot.slot < 0 ||
      snapshot.slot >= SLOT_COUNT ||
      seenSlots.has(snapshot.slot) ||
      typeof snapshot.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(snapshot.sha256) ||
      !Number.isSafeInteger(snapshot.size) ||
      snapshot.size <= SQLITE_HEADER.length ||
      typeof snapshot.updatedAt !== "string" ||
      !Number.isFinite(Date.parse(snapshot.updatedAt))
    ) {
      throw new Error("[R2] Backup manifest failed validation.");
    }
    seenSlots.add(snapshot.slot);
  }
  return value as BackupManifest;
}

/**
 * Uploads a completed SQLite snapshot using the R2 S3-compatible API.
 * A three-slot rotation keeps the current and two previous snapshots. The manifest
 * is published only after the SQLite object has been uploaded successfully.
 */
export async function uploadSqliteBackupToR2(backupFile: string): Promise<boolean> {
  const config = getR2Config();
  if (!config) return false;

  const snapshot = await fs.promises.readFile(backupFile);
  if (
    snapshot.length <= SQLITE_HEADER.length ||
    !snapshot.subarray(0, SQLITE_HEADER.length).equals(SQLITE_HEADER)
  ) {
    throw new Error("[R2] Refusing to upload a file that is not a valid SQLite snapshot.");
  }

  const current = await readManifest(config);
  const slot = current ? (current.snapshots[0].slot + 1) % SLOT_COUNT : 0;
  const checksum = sha256(snapshot);
  const objectResponse = await signedRequest(config, "PUT", slotKey(config, slot), snapshot);
  if (!objectResponse.ok) {
    const detail = (await objectResponse.text()).slice(0, 300);
    throw new Error(`[R2] SQLite upload failed (HTTP ${objectResponse.status}): ${detail}`);
  }

  const latest: BackupSnapshot = {
    slot,
    sha256: checksum,
    size: snapshot.length,
    updatedAt: new Date().toISOString(),
  };
  const manifest: BackupManifest = {
    schema: "omniroute-r2-backup-v1",
    snapshots: [latest, ...(current?.snapshots ?? []).filter((entry) => entry.slot !== slot)].slice(
      0,
      SLOT_COUNT
    ),
  };
  const manifestResponse = await signedRequest(
    config,
    "PUT",
    manifestKey(config),
    Buffer.from(JSON.stringify(manifest), "utf8")
  );
  if (!manifestResponse.ok) {
    const detail = (await manifestResponse.text()).slice(0, 300);
    throw new Error(
      `[R2] SQLite uploaded, but publishing the backup manifest failed (HTTP ${manifestResponse.status}): ${detail}`
    );
  }

  console.log(
    `[R2] SQLite snapshot uploaded (${snapshot.length} bytes, slot ${slot}, sha256 ${checksum.slice(0, 12)}…)`
  );
  return true;
}

/**
 * Restore only when the normal SQLite file is absent. Existing local data is never
 * replaced. A failed download/checksum causes startup to fail rather than silently
 * initializing an empty database over the operator's missing data.
 */
export async function restoreR2BackupBeforeDatabaseInit(): Promise<boolean> {
  const config = getR2Config();
  if (!config || TRUE_CLOUD_RUNTIME) return false;

  const dataDir = resolveWritableDataDir({ isCloud: false });
  const databaseFile = path.join(dataDir, "storage.sqlite");
  if (fs.existsSync(databaseFile)) return false;

  const manifest = await readManifest(config);
  if (!manifest) {
    console.log("[R2] No previous SQLite backup found; starting with a new database.");
    return false;
  }

  await fs.promises.mkdir(dataDir, { recursive: true });
  const failures: string[] = [];

  for (const candidate of manifest.snapshots) {
    let temporaryFile: string | null = null;
    try {
      const response = await signedRequest(config, "GET", slotKey(config, candidate.slot));
      if (!response.ok) {
        throw new Error(`download returned HTTP ${response.status}`);
      }

      const snapshot = Buffer.from(await response.arrayBuffer());
      if (
        snapshot.length !== candidate.size ||
        sha256(snapshot) !== candidate.sha256 ||
        snapshot.length <= SQLITE_HEADER.length ||
        !snapshot.subarray(0, SQLITE_HEADER.length).equals(SQLITE_HEADER)
      ) {
        throw new Error("download failed size, checksum, or SQLite header validation");
      }

      temporaryFile = path.join(
        dataDir,
        `.storage.sqlite.r2-restore-${process.pid}-${Date.now()}.tmp`
      );
      await fs.promises.writeFile(temporaryFile, snapshot, { flag: "wx", mode: 0o600 });

      // Verify SQLite's own integrity check before making the restored file live.
      const { tryOpenSync } = await import("./adapters/driverFactory");
      const validationDb = tryOpenSync(temporaryFile, { readonly: true, fileMustExist: true });
      if (!validationDb) throw new Error("SQLite could not open the downloaded snapshot");
      try {
        const integrity = validationDb.pragma("integrity_check") as Array<{
          integrity_check?: string;
        }>;
        if (integrity[0]?.integrity_check !== "ok") {
          throw new Error("SQLite integrity_check did not return ok");
        }
      } finally {
        validationDb.close();
      }

      try {
        // link() is exclusive: a concurrent local DB creation wins and is never overwritten.
        await fs.promises.link(temporaryFile, databaseFile);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw error;
      }

      console.log(
        `[R2] Restored SQLite database (${snapshot.length} bytes, updated ${candidate.updatedAt}).`
      );
      return true;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      failures.push(`slot ${candidate.slot}: ${detail}`);
      console.warn(`[R2] Snapshot slot ${candidate.slot} could not be restored:`, detail);
    } finally {
      if (temporaryFile) {
        await fs.promises.rm(temporaryFile, { force: true }).catch(() => undefined);
      }
    }
  }

  throw new Error(
    `[R2] No valid SQLite recovery snapshot could be restored: ${failures.join("; ")}`
  );
}

let schedulerStarted = false;
let backupInFlight = false;

/** Starts the external backup schedule independently of the dashboard's local-backup toggle. */
export function startR2BackupScheduler(): boolean {
  const config = getR2Config();
  if (!config || TRUE_CLOUD_RUNTIME || schedulerStarted) return false;

  schedulerStarted = true;
  const rawMinutes = Number(envValue("R2_BACKUP_INTERVAL_MINUTES") ?? "30");
  const intervalMinutes = Number.isFinite(rawMinutes)
    ? Math.min(1440, Math.max(5, Math.floor(rawMinutes)))
    : 30;
  const intervalMs = intervalMinutes * 60 * 1000;

  const runBackup = async () => {
    if (backupInFlight) return;
    backupInFlight = true;
    try {
      const [{ backupDbFileAwaited }, { DB_BACKUPS_DIR }] = await Promise.all([
        import("./backup"),
        import("./core"),
      ]);
      const result = await backupDbFileAwaited("r2-auto", { mandatory: true });
      if (!result) {
        console.warn("[R2] Scheduled backup skipped because the local SQLite database is not ready.");
        return;
      }
      if (!DB_BACKUPS_DIR) {
        throw new Error("[R2] Local SQLite backup directory is unavailable in this runtime.");
      }
      await uploadSqliteBackupToR2(path.join(DB_BACKUPS_DIR, result.filename));
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.warn("[R2] Scheduled backup failed; it will be retried at the next interval:", detail);
    } finally {
      backupInFlight = false;
    }
  };

  void runBackup();
  const timer = setInterval(() => void runBackup(), intervalMs);
  timer.unref?.();
  console.log(`[R2] Cloudflare R2 backup schedule enabled (every ${intervalMinutes} minutes).`);
  return true;
}
