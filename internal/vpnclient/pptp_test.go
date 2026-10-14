//go:build linux

package vpnclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func pptpTestLink(mppe string) model.RouterLink {
	return model.RouterLink{
		Id:         7,
		Name:       "测试路由",
		Protocol:   "pptp",
		RemoteHost: "116.59.15.247",
		RemotePort: 1723,
		LanSubnet:  "192.168.10.0/24",
		Mppe:       mppe,
	}
}

// TestBuildPPTPOptionsGolden：默认档必须含 nodefaultroute + require-mppe-128 +
// mppe-stateful（2026-10-14 真机实测：缺 mppe-stateful 会卡 CCP），绝不能含 defaultroute。
func TestBuildPPTPOptionsGolden(t *testing.T) {
	out := buildPPTPOptions(pptpTestLink("require-mppe-128"))
	for _, want := range []string{
		"nodefaultroute",   // 铁律
		"noipdefault",      //
		"require-mppe-128", //
		"mppe-stateful",    // 真机实测必需
		"noauth",           //
	} {
		if !strings.Contains(out, want+"\n") && !strings.Contains(out, want+" ") {
			t.Errorf("options 缺少 %q\n%s", want, out)
		}
	}
	for _, banned := range []string{"defaultroute", "usepeerdns"} {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, banned) {
				t.Errorf("options 绝不能含 %q（行: %q）", banned, line)
			}
		}
	}
}

// TestBuildPPTPOptionsMppeTiers：三档行为。
func TestBuildPPTPOptionsMppeTiers(t *testing.T) {
	out := buildPPTPOptions(pptpTestLink("require-mppe"))
	if !strings.Contains(out, "require-mppe\n") || !strings.Contains(out, "mppe-stateful\n") {
		t.Errorf("require-mppe 档应同时有 require-mppe + mppe-stateful\n%s", out)
	}
	if strings.Contains(out, "require-mppe-128") {
		t.Errorf("require-mppe 档不应含 require-mppe-128\n%s", out)
	}

	out = buildPPTPOptions(pptpTestLink("nomppe"))
	if strings.Contains(out, "mppe") {
		t.Errorf("nomppe 档不应含任何 mppe 行\n%s", out)
	}
	if !strings.Contains(out, "nodefaultroute") {
		t.Errorf("nomppe 档仍必须有 nodefaultroute\n%s", out)
	}
}

func TestChapSecretsLine(t *testing.T) {
	link := pptpTestLink("require-mppe-128")
	auth := routerAuth{Username: "vpnuser", Password: "s3cret"}
	line := chapSecretsLine(link, auth)
	want := "vpnuser rl-7 s3cret *\n"
	if line != want {
		t.Fatalf("chap-secrets 行不符:\n got=%q\nwant=%q", line, want)
	}
	// 含空格的密码应加引号。
	auth.Password = "a b"
	line = chapSecretsLine(link, auth)
	if !strings.Contains(line, `"a b"`) {
		t.Fatalf("含空格密码应加引号: %q", line)
	}
}

func TestSyncChapSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chap-secrets")
	link := pptpTestLink("require-mppe-128")
	auth := routerAuth{Username: "vpnuser", Password: "s3cret"}

	// 写入两次应幂等（只有一行）。
	for i := 0; i < 2; i++ {
		if err := syncChapSecrets(path, link.Id, chapSecretsLine(link, auth)); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || lines[0] != "vpnuser rl-7 s3cret *" {
		t.Fatalf("幂等写入失败: %q", data)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("chap-secrets 权限应为 0600，实际 %o", fi.Mode().Perm())
	}

	// 第二个连接共存。
	link2 := link
	link2.Id = 8
	auth2 := routerAuth{Username: "other", Password: "pw"}
	if err := syncChapSecrets(path, link2.Id, chapSecretsLine(link2, auth2)); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if got := strings.Count(string(data), "\n"); got != 2 {
		t.Fatalf("两行共存失败: %q", data)
	}

	// 删除 id=7 的行。
	if err := syncChapSecrets(path, 7, ""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "rl-7") || !strings.Contains(string(data), "rl-8") {
		t.Fatalf("删除指定行失败: %q", data)
	}
}
