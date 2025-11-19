#!/usr/bin/env bash

# 如果你的 SDE 沒有 export，請自行修改這行
# export SDE=/root/bf-sde-9.7.0
# 若你的系統環境已經有 SDE 就不用改

$SDE/install/bin/ucli << 'EOF'
pm

# === Port 140 ===
port-add 140 10G NONE
port-enb 140

# === Port 141 ===
port-add 141 10G NONE
port-enb 141

# === Port 142 ===
port-add 142 10G NONE
port-enb 142

# === Port 143 ===
port-add 143 10G NONE
port-enb 143

quit
EOF
