import express from 'express';
import { createHash } from 'crypto';
import { exportHandler } from './routes/export';
import { signSession, warmCache } from './security/tokens';

const app = express();

app.post('/sessions', (req, res) => {
  res.json({ token: signSession(req.body.id) });
});

app.get('/digest', (req, res) => {
  res.send(createHash('sha1').update(String(req.query.q)).digest('hex'));
});

app.get('/export', exportHandler);

app.listen(8080, () => {
  warmCache();
});
