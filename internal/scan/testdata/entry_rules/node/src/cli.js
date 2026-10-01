const crypto = require('crypto');

function run() {
  return crypto.createHash('sha512-256').update('cli').digest('hex');
}

if (require.main === module) {
  run();
}
