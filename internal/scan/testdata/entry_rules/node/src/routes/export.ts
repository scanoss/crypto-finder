import { createHash } from 'crypto';

export function exportHandler(req: unknown, res: { send(body: string): void }) {
  res.send(createHash('md5').update('export').digest('hex'));
}
