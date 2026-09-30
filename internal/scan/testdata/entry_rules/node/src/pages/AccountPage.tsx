import { Statements } from '../components/Statements';

export default function AccountPage({ email }: { email: string }) {
  return (
    <main>
      <Statements email={email} />
    </main>
  );
}
