import { createHash, randomBytes } from 'crypto';

export class TokenIssuer {
  constructor(private readonly salt: string) {}

  issue(subject: string): string {
    return createHash('sha256').update(this.salt + subject).digest('hex');
  }
}

export function tokenFor(subject: string): string {
  const issuer = new TokenIssuer(randomBytes(16).toString('hex'));
  return issuer.issue(subject);
}
