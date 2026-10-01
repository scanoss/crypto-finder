import { createHash } from 'crypto';
import { Memo } from 'memo-store';

const memo = new Memo();

// .get(path, fn) on a receiver that no router package provides: the callback
// runs when get runs, it is not a route.
memo.get('/session', () => createHash('sha512-224').update('memo').digest('hex'));
