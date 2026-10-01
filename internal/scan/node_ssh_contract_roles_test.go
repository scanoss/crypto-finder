// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// The pre-10.0 default export, named as that release's README names it: the
// constructor is keyed by the local name, and both spellings consumers use
// type the client so connect has its factory.
const nodeSSHConsumer = `const node_ssh = require('node-ssh');

async function deploy(config) {
  const ssh = new node_ssh();
  await ssh.connect(config);
  return ssh;
}

module.exports = { deploy };
`

func TestNodeSSHSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	asset := cAsset(5, 5, 9, 28, "await ssh.connect(config);",
		"javascript.node-ssh.protocol.ssh.connect",
		map[string]string{"assetType": "protocol", "api": "node-ssh.NodeSSH.connect"})
	want := map[string]string{"node-ssh.node_ssh.<init>": "factory"}
	assertNodeSupportingRoles(t, "deploy.js", nodeSSHConsumer, asset, want)
}
