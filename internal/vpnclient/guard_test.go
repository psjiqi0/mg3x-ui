//go:build linux

package vpnclient

import (
	"strings"
	"testing"
)

// TestFingerprintIPRouteDefault：指纹只关心 via/dev/metric，行序不影响。
func TestFingerprintIPRouteDefault(t *testing.T) {
	a := "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n" +
		"default via 10.0.0.2 dev eth1 proto static metric 200\n"
	b := "default via 10.0.0.2 dev eth1 proto static metric 200\n" +
		"default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"
	if fingerprintIPRouteDefault(a) != fingerprintIPRouteDefault(b) {
		t.Fatal("行序不同的同一路由表指纹应相同")
	}
	changed := "default via 10.0.0.99 dev eth0 proto dhcp metric 100\n"
	if fingerprintIPRouteDefault(a) == fingerprintIPRouteDefault(changed) {
		t.Fatal("网关变化后指纹应不同")
	}
	// proto/expires 等易变字段不应影响指纹。
	noisy := "default via 10.0.0.1 dev eth0 proto dhcp metric 100 expires 86399sec\n" +
		"default via 10.0.0.2 dev eth1 proto static metric 200\n"
	if fingerprintIPRouteDefault(a) != fingerprintIPRouteDefault(noisy) {
		t.Fatal("易变字段（expires）不应影响指纹")
	}
}

// /proc/net/route 夹具：默认路由经 eth0；192.168.225.0/24 经 tun0。
// 注意小端 hex：192.168.225.0 -> "00E1A8C0"，掩码 /24 -> "00FFFFFF"。
const procNetRouteFixture = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
tun0	00E1A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

func TestParseProcNetRoute(t *testing.T) {
	routes := parseProcNetRoute(procNetRouteFixture)
	if len(routes) != 3 {
		t.Fatalf("应解析出 3 条路由，实际 %d", len(routes))
	}
	if routes[0].Dest.String() != "0.0.0.0" || routes[0].Gateway.String() != "192.168.0.1" {
		t.Fatalf("默认路由解析错误: %+v", routes[0])
	}
	if routes[2].Dest.String() != "192.168.225.0" || routes[2].Bits != 24 || routes[2].Iface != "tun0" {
		t.Fatalf("tun0 路由解析错误: %+v", routes[2])
	}
	fp := fingerprintProcNetRouteDefault(procNetRouteFixture)
	if !strings.Contains(fp, "eth0|192.168.0.1|100") {
		t.Fatalf("默认路由指纹格式错误: %q", fp)
	}
}

func TestScopedRoutePresentIn(t *testing.T) {
	ok, err := scopedRoutePresentIn(procNetRouteFixture, "192.168.225.0/24", "tun0")
	if err != nil || !ok {
		t.Fatalf("tun0 的 scoped 路由应存在: ok=%v err=%v", ok, err)
	}
	ok, err = scopedRoutePresentIn(procNetRouteFixture, "192.168.225.0/24", "eth0")
	if err != nil || ok {
		t.Fatalf("eth0 上不应有该 scoped 路由: ok=%v err=%v", ok, err)
	}
	ok, err = scopedRoutePresentIn(procNetRouteFixture, "192.168.1.0/24", "tun0")
	if err != nil || ok {
		t.Fatalf("不相关的子网不应命中: ok=%v err=%v", ok, err)
	}
	if _, err := scopedRoutePresentIn(procNetRouteFixture, "not-a-subnet", "tun0"); err == nil {
		t.Fatal("非法子网应报错")
	}
}
