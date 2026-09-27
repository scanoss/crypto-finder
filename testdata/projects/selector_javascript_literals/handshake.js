const noise = require("noise-protocol")

function handshakes(prologue, suffix) {
  const doubleQuoted = noise.initialize("NN", true, prologue)
  const singleQuoted = noise.initialize('NN', true, prologue)
  const template = noise.initialize(`NN`, true, prologue)
  const escaped = noise.initialize('N\u004E', true, prologue)
  const substituted = noise.initialize(`N${suffix}`, true, prologue)
  const other = noise.initialize('KK', true, prologue)
  return [doubleQuoted, singleQuoted, template, escaped, substituted, other]
}

module.exports = handshakes
