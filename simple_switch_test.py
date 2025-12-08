#!/usr/bin/env python3
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP

import threading
import time


class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 1) user forwarding table
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")

        # 2) sampling table
        self.port_sampling_tbl = self.bfrt_info.table_get("MyIngress.port_sampling_rate")

        # 3) port_agent table
        self.port_agent_tbl = self.bfrt_info.table_get("MyIngress.set_port_agent")

        # 4) PRE tables
        self.pre_node_tbl = self.bfrt_info.table_get("$pre.node")
        self.pre_mgid_tbl = self.bfrt_info.table_get("$pre.mgid")

        self.cleanUp()

    def runTest(self):

        # =========================================================
        # (1) MyIngress.ingress_port_forward
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
        print("✅ ingress_port_forward 規則已寫入")

        # =========================================================
        # (2) MyIngress.port_sampling_rate
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
        print("✅ port_sampling_rate 規則已寫入")

        # =========================================================
        # (3) MyIngress.set_port_agent
        #     等價於 CLI：
        #     set_port_agent.add_with_set_sample_hd(ingress_port=140,
        #         agent_addr=0x0a0a0301, agent_id=1)
        #     set_port_agent.add_with_set_sample_hd(ingress_port=143,
        #         agent_addr=0x0a0a0302, agent_id=2)
        # =========================================================
        # ⚠️ 注意：這裡的 key field 名稱是 "ingress_port"（沒有 ig_intr_md.）
        pa1_key = self.port_agent_tbl.make_key([
            gc.KeyTuple("ingress_port", 140)
        ])
        pa1_data = self.port_agent_tbl.make_data(
            [
                gc.DataTuple("agent_addr", 0x0a0a0301),
                gc.DataTuple("agent_id", 1)
            ],
            "MyIngress.set_sample_hd"
        )

        pa2_key = self.port_agent_tbl.make_key([
            gc.KeyTuple("ingress_port", 143)
        ])
        pa2_data = self.port_agent_tbl.make_data(
            [
                gc.DataTuple("agent_addr", 0x0a0a0302),
                gc.DataTuple("agent_id", 2)
            ],
            "MyIngress.set_sample_hd"
        )

        self.port_agent_tbl.entry_add(
            self.dev_tgt,
            [pa1_key, pa2_key],
            [pa1_data, pa2_data]
        )
        print("✅ set_port_agent 規則已寫入")

        # =========================================================
        # (4) PRE multicast: $pre.node / $pre.mgid
        # =========================================================
        node_id = 1
        dev_port_list = [32]   # device port 32 (對應 PTF port 320 via ports.json)

        # $pre.node
        node_key = self.pre_node_tbl.make_key([
            gc.KeyTuple("$pre.node_id", node_id)
        ])
        node_data = self.pre_node_tbl.make_data([
            gc.DataTuple("$pre.dev_port", int_arr_val=dev_port_list),
            gc.DataTuple("$pre.lag_id", int_arr_val=[]),
            gc.DataTuple("$pre.mcast_rid", 1),
            gc.DataTuple("$pre.l1_xid", int_arr_val=[0]),
            gc.DataTuple("$pre.l1_xid_valid", bool_arr_val=[False]),
        ])
        self.pre_node_tbl.entry_add(self.dev_tgt, [node_key], [node_data])
        print("✅ $pre.node 已寫入")

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
        print("✅ $pre.mgid 已寫入")

        # =========================================================
        # (5) 啟動背景 thread：每秒送封包到 PTF port 320
        # =========================================================
        t = threading.Thread(target=self.send_pkt_every_second, daemon=True)
        t.start()

        # 不讓測試結束
        while True:
            time.sleep(1)

    def send_pkt_every_second(self):
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
            IP(src="10.0.0.1", dst="10.0.0.2") /
            UDP(sport=1234, dport=5678) /
            b"test"
        )

        count = 0
        input("按 Enter 後開始每秒送封包到 PTF port 320...\n")

        while True:
            count += 1
            print("{}, send_packet() to port 320".format(count))
            send_packet(self, 320, pkt)
            time.sleep(1)

    def cleanUp(self):
        # 目前不清 table
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
