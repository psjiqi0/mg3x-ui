package amneziawgnet

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// clientUAPITestInstance builds a minimal inbound Instance with one
// server-style peer; client-role tests set Peer.Endpoint and
// Peer.PersistentKeepalive on top of it.
func clientUAPITestInstance(t *testing.T) amneziawg.Instance {
	t.Helper()
	priv, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return amneziawg.Instance{
		PrivateKey: priv,
		ListenPort: 51820,
		Obfuscation: amneziawg.Obfuscation31{
			S1: 20, S2: 20, S3: 20, S4: 20,
		},
		Peers: []amneziawg.Peer{{
			Email:      "router@example.com",
			PublicKey:  pub,
			AllowedIPs: []string{"192.168.225.0/24"},
		}},
	}
}

// TestClientUAPIConfig_EmitsEndpointAndKeepalive is the client-role proof for
// RELAY_DESIGN.md section 7.1: a peer with Endpoint/PersistentKeepalive set
// gets the two extra UAPI lines inside its peer block.
func TestClientUAPIConfig_EmitsEndpointAndKeepalive(t *testing.T) {
	inst := clientUAPITestInstance(t)
	inst.Peers[0].Endpoint = "203.0.113.46:51820"
	inst.Peers[0].PersistentKeepalive = 25

	conf, err := buildUAPIConfig(inst, DeviceOptions{})
	if err != nil {
		t.Fatalf("buildUAPIConfig: %v", err)
	}
	if !strings.Contains(conf, "endpoint=203.0.113.46:51820\n") {
		t.Errorf("expected endpoint=203.0.113.46:51820 line, got:\n%s", conf)
	}
	if !strings.Contains(conf, "persistent_keepalive_interval=25\n") {
		t.Errorf("expected persistent_keepalive_interval=25 line, got:\n%s", conf)
	}
}

// TestClientUAPIConfig_ServerPeerOmitsClientLines locks the server-side
// contract: a peer with empty Endpoint and zero PersistentKeepalive (the
// existing server usage) must not gain any new line -- the rendered UAPI is
// byte-for-byte what it was before these fields existed.
func TestClientUAPIConfig_ServerPeerOmitsClientLines(t *testing.T) {
	inst := clientUAPITestInstance(t)

	conf, err := buildUAPIConfig(inst, DeviceOptions{})
	if err != nil {
		t.Fatalf("buildUAPIConfig: %v", err)
	}
	if strings.Contains(conf, "endpoint=") {
		t.Errorf("server-role peer must not emit an endpoint= line, got:\n%s", conf)
	}
	if strings.Contains(conf, "persistent_keepalive") {
		t.Errorf("server-role peer must not emit a persistent_keepalive line, got:\n%s", conf)
	}
}
