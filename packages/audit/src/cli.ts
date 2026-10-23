#!/usr/bin/env node
/**
 * Independent AgentTrust audit verifier.
 *
 *   agenttrust-verify --export audit-export.json --anchors <dir>
 *
 * - `audit-export.json` comes from GET /v1/audit/export (events + public keys).
 * - `<dir>` is the write-once anchor storage (local adapter layout:
 *   <dir>/<organizationId>/anchor-<toSequence>.json), read DIRECTLY from storage,
 *   never from the AgentTrust API, so a compromised database cannot fake them.
 *
 * Uses only public keys. Exit code 0 = valid, 1 = problems found.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { SealedAuditEvent } from './chain';
import { verifyAgainstAnchors, type AnchoredVerificationResult, type SignedAnchor } from './anchor';

export interface AuditExport {
  organizationId: string;
  events: SealedAuditEvent[];
  publicKeys: { keyId: string; publicKeyPem: string }[];
}

export function readAnchorsFromDirectory(dir: string, organizationId: string): SignedAnchor[] {
  const orgDir = path.join(dir, organizationId);
  let files: string[] = [];
  try {
    files = readdirSync(orgDir).filter((f) => /^anchor-\d+\.json$/.test(f));
  } catch {
    return [];
  }
  return files.map((f) => JSON.parse(readFileSync(path.join(orgDir, f), 'utf8')) as SignedAnchor);
}

export function verifyExport(exp: AuditExport, anchors: SignedAnchor[], trustedKeys?: { keyId: string; publicKeyPem: string }[]): AnchoredVerificationResult {
  // Prefer independently obtained public keys; fall back to those in the export.
  const keys = new Map<string, KeyObject>();
  for (const k of trustedKeys ?? exp.publicKeys) keys.set(k.keyId, createPublicKey(k.publicKeyPem));
  return verifyAgainstAnchors(exp.events, anchors, (id) => keys.get(id) ?? null);
}

function main(argv: string[]) {
  const arg = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const exportPath = arg('--export');
  const anchorDir = arg('--anchors');
  const keyPath = arg('--public-key');
  if (!exportPath || !anchorDir) {
    console.error('usage: agenttrust-verify --export <audit-export.json> --anchors <anchor-dir> [--public-key <key.pem> --key-id <id>]');
    process.exit(2);
  }
  const exp = JSON.parse(readFileSync(exportPath, 'utf8')) as AuditExport;
  const trusted = keyPath ? [{ keyId: arg('--key-id') ?? exp.publicKeys[0]?.keyId ?? 'unknown', publicKeyPem: readFileSync(keyPath, 'utf8') }] : undefined;
  const result = verifyExport(exp, readAnchorsFromDirectory(anchorDir, exp.organizationId), trusted);
  console.log(JSON.stringify({ organizationId: exp.organizationId, ...result, chain: { valid: result.chain.valid, eventsChecked: result.chain.eventsChecked } }, null, 2));
  process.exit(result.valid ? 0 : 1);
}

if (require.main === module) main(process.argv.slice(2));
