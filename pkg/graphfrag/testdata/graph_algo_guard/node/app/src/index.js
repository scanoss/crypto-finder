const { Hasher, digest } = require('dep');
const { tokenFor } = require('./token');
const { seal } = require('./seal');

function main() {
  const hasher = new Hasher('key');
  console.log(hasher.mac('data'));
  console.log(digest('data'));
  console.log(tokenFor('user'));
  seal('data').then(console.log);
}

main();
