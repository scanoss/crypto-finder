// A transitive dependency that does the hashing.
const crypto = require("crypto");

function usedHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function unusedHash(data) {
  return crypto.createHash("sha512").update(data).digest("hex");
}

module.exports = { usedHash, unusedHash };
