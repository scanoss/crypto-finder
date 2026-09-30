const crypto = require('crypto');

function fingerprint(data) {
  return crypto.createHash('sha3-256').update(data).digest('hex');
}

module.exports = { fingerprint };
