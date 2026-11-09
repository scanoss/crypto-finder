const crypto = require('crypto');

function stretch(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');
}

function lock(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function seal(password, data) {
  const salt = crypto.randomBytes(16);
  const key = stretch(password, salt);
  const iv = crypto.randomBytes(16);
  return Buffer.concat([salt, iv, lock(key, iv, data)]);
}

function sealWithFixedIv(key, data) {
  let iv = crypto.randomBytes(16);
  iv = Buffer.alloc(16);
  return lock(key, iv, data);
}

module.exports = { seal, sealWithFixedIv };
