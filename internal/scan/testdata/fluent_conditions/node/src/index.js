const { avatarCacheKey, sessionTag } = require('./avatar');

function main() {
  console.log(avatarCacheKey(process.argv[2]), sessionTag(process.argv[3]));
}

if (require.main === module) {
  main();
}
