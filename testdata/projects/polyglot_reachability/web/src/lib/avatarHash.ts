import { createHash } from 'crypto';

export function avatarCacheKey(email: string): string {
  return createHash('md5').update(email.trim().toLowerCase()).digest('hex');
}

export function avatarUrl(email: string): string {
  return `https://avatars.example.com/${avatarCacheKey(email)}.png`;
}

export function legacyEtag(body: string): string {
  return createHash('sha1').update(body).digest('hex');
}
