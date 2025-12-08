#!/usr/bin/env python3
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

# 用 PTF 送封包
from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP

import threading
import time


class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        # pipe_id=0xFFFF 代表所有 pipe
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # 跟 switchd 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)

        # 取得 bfrt 資訊
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 1) user 定義的 forwarding table
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")

        # 2) port sampling table
        self.port_sampling_tbl = self.bfrt_info.table_get("MyIngress.port_sampling_rate")

        # 3) PRE multicast tables
        self.pre_node_tbl = self.bfrt_info.table_get("$pre.node")
        self.pre_mgid_tbl = self.bfrt_info.table_get("$pre.mgid")

        # 如果之後要用到 BfRuntimeTest 內建 clean 機制可以用這個
        self.tables = [
            self.ing_tbl,
            self.port_sampling_tbl,
            self.pre_node_tbl,
            self.pre_mgid_tbl,
        ]

        # 目前我們自己控制，不清 table
        self.cleanUp()

    def runTest(self):
        # =========================================================
        # (1) 寫入 MyIngress.ingress_port_forward 規則
        # =========================================================
        k1 = self.ing_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 140)
        ])
        d1 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 141)],
            "MyIngress.set_out_port"
        )

        k2 = self.ing_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 141)
        ])
        d2 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 140)],
            "MyIngress.set_out_port"
        )

        k3 = self.ing_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 142)
        ])
        d3 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 143)],
            "MyIngress.set_out_port"
        )

        k4 = self.ing_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 143)
        ])
        d4 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 142)],
            "MyIngress.set_out_port"
        )

        self.ing_tbl.entry_add(
            self.dev_tgt,
            [k1, k2, k3, k4],
            [d1, d2, d3, d4]
        )
        print("✅ ingress_port_forward 規則已寫入完成!!!!")

        # =========================================================
        # (2) 寫入 MyIngress.port_sampling_rate 規則
        #     等價於：
        #     simple_switch.pipe.MyIngress.port_sampling_rate
        #       .add_with_set_sampling_rate(ingress_port=140, sampling_rate=99)
        #     simple_switch.pipe.MyIngress.port_sampling_rate
        #       .add_with_set_sampling_rate(ingress_port=143, sampling_rate=49)
        # =========================================================
        ks1 = self.port_sampling_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 140)
        ])
        ds1 = self.port_sampling_tbl.make_data(
            [gc.DataTuple("sampling_rate", 99)],
            "MyIngress.set_sampling_rate"
        )

        ks2 = self.port_sampling_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 143)
        ])
        ds2 = self.port_sampling_tbl.make_data(
            [gc.DataTuple("sampling_rate", 49)],
            "MyIngress.set_sampling_rate"
        )

        self.port_sampling_tbl.entry_add(
            self.dev_tgt,
            [ks1, ks2],
            [ds1, ds2]
        )
        print("✅ port_sampling_rate 規則已寫入完成!!!!")

        # =========================================================
        # (3) 設定 PRE multicast
        #     等價於 CLI：
        #     pre.node.add(DEV_PORT=[32], MULTICAST_LAG_ID=[],
        #                  MULTICAST_NODE_ID=1, MULTICAST_RID=1)
        #     pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[1],
        #                  MULTICAST_NODE_L1_XID=[0],
        #                  MULTICAST_NODE_L1_XID_VALID=[0])
        # =========================================================
        node_id = 1
        dev_port_list = [32]  # device port 32（對應 PTF port 320，靠 ports.json map）

        # $pre.node
        node_key = self.pre_node_tbl.make_key([
            gc.KeyTuple("$pre.node_id", node_id)
        ])

        node_data = self.pre_node_tbl.make_data([
            # DEV_PORT=[32]
            gc.DataTuple("$pre.dev_port", int_arr_val=dev_port_list),
            # MULTICAST_LAG_ID=[]（如無此欄可刪掉這行，看你 SDE 版本）
            gc.DataTuple("$pre.lag_id", int_arr_val=[]),
            # MULTICAST_RID=1
            gc.DataTuple("$pre.mcast_rid", 1),
            # L1 欄位不使用，給預設值
            gc.DataTuple("$pre.l1_xid", int_arr_val=[0]),
            gc.DataTuple("$pre.l1_xid_valid", bool_arr_val=[False]),
        ])

        self.pre_node_tbl.entry_add(self.dev_tgt, [node_key], [node_data])
        print("✅ $pre.node 已寫入 (node_id = 1, dev_port = [32])")

        # $pre.mgid
        mgid = 1
        mgid_key = self.pre_mgid_tbl.make_key([
            gc.KeyTuple("$pre.mgid", mgid)
        ])

        mgid_data = self.pre_mgid_tbl.make_data([
            gc.DataTuple("$pre.node_id", int_arr_val=[node_id]),
            gc.DataTuple("$pre.l1_xid", int_arr_val=[0]),
            gc.DataTuple("$pre.l1_xid_valid", bool_arr_val=[False]),
        ])

        self.pre_mgid_tbl.entry_add(self.dev_tgt, [mgid_key], [mgid_data])
        print("✅ $pre.mgid 已寫入 (mgid = 1, node_id = [1])")

        # =========================================================
        # (4) 啟動背景 thread：每秒從 PTF port 320 送一包
        # =========================================================
        t = threading.Thread(target=self.send_pkt_every_second, daemon=True)
        t.start()

        # 不讓測試結束，否則 thread 會被關掉
        while True:
            time.sleep(1)

    # 每秒送一個封包到 port 320（對應 dev_port 32）
    def send_pkt_every_second(self):
        # Ethernet + IPv4 + UDP payload
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
            IP(src="10.0.0.1", dst="10.0.0.2") /
            UDP(sport=1234, dport=5678) /
            b"test"
        )
        count = 0

        # 等你按 Enter 再開始送，方便你先看 log 或用 tcpdump
        input("按 Enter 開始每秒送封包到 PTF port 320...\n")

        while True:
            count += 1
            print(f"{count}, send_packet() to port 320")
            # 第 1 個參數是 test case (self)，第二個是 PTF port 號，第三個是封包
            send_packet(self, 320, pkt)
            time.sleep(1)

    def cleanUp(self):
        # 目前不清 table，保持寫入的規則
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
