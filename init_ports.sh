#!/usr/bin/env bash
set -e


$SDE/run_bfshell.sh -b << 'EOF'
ucli
pm
port-add 140 40G NONE
port-enb 140
port-add 141 40G NONE
port-enb 141
port-add 142 40G NONE
port-enb 142
port-add 143 40G NONE
port-enb 143
quit
EOF

echo "✅ Port 140/141/142/143 已開啟"
