import { createHash } from 'crypto';

export async function POST(): Promise<Response> {
  return new Response(createHash('sha224').update('key').digest('hex'));
}
