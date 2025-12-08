# simple_switch_test.py
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

# ✅ 新增：用 PTF 送封包
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

        # 跟 switchd 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)

        # 取得 bfrt 資訊
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 對應 P4 裡的 table MyIngress.ingress_port_forward
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")

        self.tables = [self.ing_tbl]
        self.cleanUp()

    def runTest(self):
        # ===== 寫入 4 條轉送規則 =====
        k1 = self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", 140)])
        d1 = self.ing_tbl.make_data([gc.DataTuple("port", 141)], "MyIngress.set_out_port")

        k2 = self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", 141)])
        d2 = self.ing_tbl.make_data([gc.DataTuple("port", 140)], "MyIngress.set_out_port")

        k3 = self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", 142)])
        d3 = self.ing_tbl.make_data([gc.DataTuple("port", 143)], "MyIngress.set_out_port")

        k4 = self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", 143)])
        d4 = self.ing_tbl.make_data([gc.DataTuple("port", 142)], "MyIngress.set_out_port")

        self.ing_tbl.entry_add(
            self.dev_tgt,
            [k1, k2, k3, k4],
            [d1, d2, d3, d4]
        )
        print("✅ ingress_port_forward 規則已寫入完成!!!!")

        # ===== 啟動背景 thread 每秒送一包到 port 140 =====
        t = threading.Thread(target=self.send_pkt_every_second, daemon=True)
        t.start()

        # 不讓測試結束，否則 thread 會被關掉
        while True:
            time.sleep(1)

    # 每秒送一個封包到 port 140
    def send_pkt_every_second(self):
        # 做一個合法 Ethernet + IPv4 + UDP 封包，會被你的 parser 正常解析
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
            IP(src="10.0.0.1", dst="10.0.0.2") /
            UDP(sport=1234, dport=5678) /
            b"test"
        )

        while True:
            print("➡️  send_packet() to port 140 ...")
            # 第 1 個參數是 test case (self)，第二個是 port 號，第三個是封包
            send_packet(self, 320, pkt)
            time.sleep(1)

    def cleanUp(self):
        # 不清 table，保持你寫入的規則
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
