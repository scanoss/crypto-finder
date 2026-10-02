const crypto = require('crypto');

class Hasher {
  constructor(key) {
    this.key = key;
  }

  mac(data) {
    return crypto.createHmac('sha256', this.key).update(data).digest('hex');
  }
}

function digest(data) {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

module.exports = { Hasher, digest };
