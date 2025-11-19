#!/usr/bin/env bash
set -e

# 把指令餵給 run_bfshell.sh（注意這裡沒有加 -b）
$SDE/run_bfshell.sh << 'EOF'
ucli
pm

# 開啟 port 140
port-add 140 40G NONE
port-enb 140

# 開啟 port 141
port-add 141 40G NONE
port-enb 141

# 開啟 port 142
port-add 142 40G NONE
port-enb 142

# 開啟 port 143
port-add 143 40G NONE
port-enb 143

quit
EOF

echo "✅ Port 140 / 141 / 142 / 143 已經開啟完成"
