const crypto = require("crypto");
const transliba = require("transliba");

function fingerprint(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function legacy(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

function main() {
  const data = Buffer.from("payload");
  console.log(fingerprint(data));
  console.log(transliba.used(data));
}

main();
