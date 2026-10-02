const { Hasher, digest } = require('dep');
const { tokenFor } = require('./token');

function main() {
  const hasher = new Hasher('key');
  console.log(hasher.mac('data'));
  console.log(digest('data'));
  console.log(tokenFor('user'));
}

main();
