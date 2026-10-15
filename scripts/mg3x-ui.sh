#!/bin/bash
# mg3x-ui 管理脚本 (Docker 版)
# 自动探测源码目录
for d in /root/3x-ui-src /root/mg3x-ui "$HOME/mg3x-ui" /opt/mg3x-ui; do
  if [ -f "$d/docker-compose.relay.yml" ]; then SRC="$d"; break; fi
done
[ -z "$SRC" ] && SRC="/root/3x-ui-src"
COMPOSE="docker compose -f $SRC/docker-compose.relay.yml"
CONTAINER=$(docker ps -a --format "{{.Names}}" | grep -m1 "3xui-relay")
DB="/etc/x-ui/x-ui.db"

set_setting() {
  python3 -c "
import sqlite3
db = sqlite3.connect(\"$DB\")
db.execute(\"DELETE FROM settings WHERE key=?\", (\"$1\",))
db.execute(\"INSERT INTO settings (key,value) VALUES (?,?)\", (\"$1\",\"$2\"))
db.commit()
"
}

get_setting() {
  python3 -c "
import sqlite3
db = sqlite3.connect(\"$DB\")
r = db.execute(\"SELECT value FROM settings WHERE key=?\", (\"$1\",)).fetchone()
print(r[0] if r else \"\")
"
}

do_status() {
  echo "=== 容器状态 ==="
  docker ps --filter "name=$CONTAINER" --format "{{.Names}}: {{.Status}}"
  echo "=== 面板 ==="
  curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:2053/ --max-time 5
  echo "=== 路由器连接 ==="
  python3 -c "
import sqlite3
db = sqlite3.connect(\"$DB\")
for r in db.execute(\"SELECT id,name,protocol,enable FROM router_links\"):
    print(f\"  #{r[0]} {r[1]} ({r[2]})\", \"启用\" if r[3] else \"禁用\")
" 2>/dev/null || echo "  (数据库不可读)"
}

do_restart() { cd $SRC && $COMPOSE restart 3xui-relay && echo "已重启"; }
do_logs() { docker logs --tail 50 -f $CONTAINER; }
do_update() {
  cd $SRC
  git pull origin main 2>&1 | tail -2
  $COMPOSE build --no-cache 3xui-relay 2>&1 | tail -1
  $COMPOSE up -d 3xui-relay
  echo "更新完成"
}
do_links() {
  python3 -c "
import sqlite3
db = sqlite3.connect(\"$DB\")
for r in db.execute(\"SELECT id,name,protocol,remote_host,lan_subnet,enable FROM router_links\"):
    print(f\"#{r[0]} {r[1]} [{r[2]}] {r[3]} -> {r[4]}\", \"ON\" if r[5] else \"OFF\")
"
}
do_chpasswd() {
  read -p "新用户名 (回车保持): " u
  read -s -p "新密码: " p; echo
  [ -n "$u" ] && python3 -c "
import sqlite3
db=sqlite3.connect(\"$DB\"); db.execute(\"UPDATE users SET username=? WHERE id=1\",(\"$u\",)); db.commit()
" && echo "用户名已更新"
  python3 -c "import bcrypt" 2>/dev/null || pip3 install --break-system-packages -q bcrypt 2>&1 | tail -1
  [ -n "$p" ] && python3 -c "
import sqlite3, bcrypt
db=sqlite3.connect(\"$DB\")
h=bcrypt.hashpw(\"$p\".encode(), bcrypt.gensalt()).decode()
db.execute(\"UPDATE users SET password=? WHERE id=1\",(h,)); db.commit()
" && echo "密码已更新"
  do_restart
}
do_chport() {
  read -p "新面板端口: " port
  if [[ "$port" =~ ^[0-9]+$ ]]; then
    set_setting "webPort" "$port"
    echo "端口已改为 $port，重启生效"
    do_restart
  else echo "端口无效"; fi
}
do_cert() {
  echo "=== Cloudflare 证书申请与绑定 ==="
  read -p "域名: " domain
  read -p "CF API Token: " cftoken; echo
  echo "Token 已输入 (长度 ${#cftoken} 字符, 开头 ${cftoken:0:4}****结尾 ****${cftoken: -4})"
  if [ ${#cftoken} -lt 20 ]; then echo "Token 太短，可能输错了"; return; fi
  [ -z "$domain" ] && { echo "域名不能为空"; return; }
  echo "dns_cloudflare_api_token = $cftoken" > /tmp/cf.ini
  chmod 600 /tmp/cf.ini
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
  certbot certonly --dns-cloudflare --dns-cloudflare-credentials /tmp/cf.ini \
    -d "$domain" -d "*.$domain" --non-interactive --agree-tos \
    --register-unsafely-without-email 2>&1 | tail -3
  rm -f /tmp/cf.ini
  if [ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]; then
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" /etc/x-ui/${domain}.crt
    cp "/etc/letsencrypt/live/$domain/privkey.pem" /etc/x-ui/${domain}.key
    set_setting "webCertFile" "/etc/x-ui/${domain}.crt"
    set_setting "webKeyFile" "/etc/x-ui/${domain}.key"
    echo "证书已绑定，重启生效"
    do_restart
    bp=$(get_setting "webBasePath")
    [ -z "$bp" ] && bp="/"
    echo "面板: https://$domain:2053$bp"
  else echo "证书申请失败"; fi
}
do_loginpath() {
  cur=$(get_setting "webBasePath")
  [ -z "$cur" ] && cur="/"
  echo "当前登录路径: $cur"
  read -p "新路径 (如 /mysecret/，回车不改): " np
  if [ -n "$np" ]; then
    [[ "$np" != /* ]] && np="/$np"
    [[ "$np" != */ ]] && np="$np/"
    set_setting "webBasePath" "$np"
    echo "已改为 $np，重启生效"
    do_restart
  fi
}

case "$1" in
  status) do_status ;;
  restart) do_restart ;;
  logs) do_logs ;;
  update) do_update ;;
  links) do_links ;;
  chpasswd) do_chpasswd ;;
  chport) do_chport ;;
  cert) do_cert ;;
  loginpath) do_loginpath ;;
  ""|menu)
    while true; do
      echo ""
      echo "=== mg3x-ui ==="
      echo "1. 状态查看"
      echo "2. 重启面板"
      echo "3. 实时日志"
      echo "4. 从 GitHub 更新"
      echo "5. 路由器连接列表"
      echo "6. 修改面板密码"
      echo "7. 修改面板端口"
      echo "8. 申请/绑定证书 (Cloudflare)"
      echo "9. 查看/修改登录路径"
      echo "0. 退出"
      read -p "选择 [0-9]: " c
      case "$c" in
        1) do_status ;; 2) do_restart ;; 3) do_logs ;;
        4) do_update ;; 5) do_links ;; 6) do_chpasswd ;;
        7) do_chport ;; 8) do_cert ;; 9) do_loginpath ;;
        0) break ;; *) echo "无效选择" ;;
      esac
    done ;;
  *) echo "用法: mg3x-ui {status|restart|logs|update|links|chpasswd|chport|cert|loginpath|menu}" ;;
esac
