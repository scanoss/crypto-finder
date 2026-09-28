import { createHash } from 'crypto';

export function etag(body: string): string {
  return createHash('sha256').update(body).digest('hex');
}
