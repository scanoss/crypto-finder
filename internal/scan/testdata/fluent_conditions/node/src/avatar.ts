import { createHash } from 'crypto';

export function avatarCacheKey(email: string): string {
  return createHash('md5').update(email.trim().toLowerCase()).digest('hex');
}

export function sessionTag(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}
