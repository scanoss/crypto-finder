import { createHash } from 'crypto';

export function avatarKey(email: string): string {
  return createHash('md5').update(email).digest('hex');
}

export function avatarUrl(email: string): string {
  return `https://avatars.example/${avatarKey(email)}.png`;
}
