// A direct dependency with no hashing of its own.
const translibb = require("translibb");

function used(data) {
  return translibb.usedHash(data);
}

function unused(data) {
  return translibb.unusedHash(data);
}

module.exports = { used, unused };
