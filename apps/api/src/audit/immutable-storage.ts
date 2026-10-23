import { Injectable } from '@nestjs/common';
import { chmod, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

/**
 * Write-once object storage for audit anchors, kept OUTSIDE the database and
 * ideally under separate access control. `putOnce` must refuse to overwrite.
 *
 * Production target: S3 with Object Lock in COMPLIANCE mode and a retention
 * period, written by a dedicated IAM role that the application database
 * administrators do not hold, in a separate AWS account. That adapter is NOT
 * implemented in this MVP (it requires the AWS SDK and account setup); the
 * interface below is what it must satisfy.
 */
export interface ImmutableStorage {
  readonly name: string;
  /** Writes an object exactly once; throws if the key already exists. Returns a URI. */
  putOnce(key: string, data: string): Promise<string>;
  get(key: string): Promise<string | null>;
  list(prefix: string): Promise<string[]>;
}

export const IMMUTABLE_STORAGE = Symbol('IMMUTABLE_STORAGE');

export class WriteOnceViolation extends Error {
  constructor(key: string) {
    super(`immutable object already exists: ${key}`);
  }
}

/**
 * Local filesystem stand-in: files are created with O_EXCL ('wx', never
 * overwritten) and made read-only (0444). Adequate for development and tests;
 * it does NOT protect against a root user on the same host.
 */
@Injectable()
export class LocalWriteOnceStorage implements ImmutableStorage {
  readonly name = 'local-write-once';

  constructor(private readonly root: string) {}

  private resolve(key: string): string {
    if (!/^[A-Za-z0-9_\-/.]+$/.test(key) || key.includes('..')) throw new Error('invalid storage key');
    return path.join(this.root, key);
  }

  async putOnce(key: string, data: string): Promise<string> {
    const file = this.resolve(key);
    await mkdir(path.dirname(file), { recursive: true });
    try {
      await writeFile(file, data, { flag: 'wx', mode: 0o444 });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new WriteOnceViolation(key);
      throw e;
    }
    await chmod(file, 0o444);
    return `file://${file}`;
  }

  async get(key: string): Promise<string | null> {
    try {
      return await readFile(this.resolve(key), 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw e;
    }
  }

  async list(prefix: string): Promise<string[]> {
    try {
      return (await readdir(this.resolve(prefix))).map((f) => `${prefix.replace(/\/$/, '')}/${f}`);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw e;
    }
  }
}
