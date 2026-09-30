import { avatarUrl } from '../lib/avatar';

export function Statements({ email }: { email: string }) {
  return <img src={avatarUrl(email)} alt="" />;
}
