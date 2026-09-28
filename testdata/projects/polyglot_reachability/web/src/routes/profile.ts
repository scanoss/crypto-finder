import { avatarUrl } from '../lib/avatarHash';
import { etag } from '../lib/etag.js';

export function renderProfile(email: string): string {
  const html = `<img src="${avatarUrl(email)}">`;
  return `${etag(html)}:${html}`;
}
