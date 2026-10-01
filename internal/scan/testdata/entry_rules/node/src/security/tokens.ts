import { createHash } from 'crypto';

export function signSession(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}

export function warmCache(): string {
  return createHash('sha384').update('warm').digest('hex');
}

// Exported, but nothing calls it and no rule makes it an entry point.
export function signLegacy(id: string): string {
  return createHash('md4').update(id).digest('hex');
}

export function fetchLegacy(): Promise<string> {
  return new Promise((resolve) => {
    resolve(createHash('ripemd160').update('batch').digest('hex'));
  });
}
