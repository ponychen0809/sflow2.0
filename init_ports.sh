#!/usr/bin/env bash
set -e

# 檢查 SDE 是否已設定
if [ -z "$SDE" ]; then
    echo "環境變數 \$SDE 尚未設定，請先執行："
    echo "  source /root/bf-sde-9.7.0/set_sde.bash"
    exit 1
fi

echo "Using SDE = $SDE"

# 把指令餵給 run_bfshell.sh（注意這裡沒有加 -b）
"$SDE/run_bfshell.sh" << 'EOF'
ucli
pm


port-add 140 10G NONE
port-enb 140


port-add 141 10G NONE
port-enb 141


port-add 142 10G NONE
port-enb 142

port-add 143 10G NONE
port-enb 143

quit
EOF

echo "✅ Port 140 / 141 / 142 / 143 已經開啟完成"
