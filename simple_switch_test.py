# simple_switch_test.py
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
import threading
import time


class SimpleSwitchTest(BfRuntimeTest):

    def setUp(self):
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        self.ing_tbl = self.bfrt_info.table_get(
            "MyIngress.ingress_port_forward"
        )

        self.tables = [self.ing_tbl]
        self.cleanUp()

    def runTest(self):
        # ======== 寫入 4 條簡單 port forwarding 規則 =========
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

        # ======== 啟動背景 thread 每秒送封包到 port 140 =========
        t = threading.Thread(target=self.send_pkt_every_second, daemon=True)
        t.start()

        # 讓測試不結束（不然 thread 會被殺掉）
        while True:
            time.sleep(1)


    # ===================== 每秒送一包到 port 140 =====================
    def send_pkt_every_second(self):
        # Ethernet + IPv4 + UDP 的合法封包 (只是一個 minimal packet)
        raw_pkt = bytes.fromhex(
            "ffffffffffff"      # dst MAC
            "001122334455"      # src MAC
            "0800"              # EtherType = IPv4
            "4500"              # Version/IHL + TOS
            "0020"              # Total Length = 32 bytes
            "0001"              # Identification
            "0000"              # Flags/Fragment
            "4011"              # TTL=64, Protocol=17(UDP)
            "0000"              # IPv4 header checksum (switch 會重算)
            "0a000001"          # src IP = 10.0.0.1
            "0a000002"          # dst IP = 10.0.0.2
            "1234"              # UDP src port
            "5678"              # UDP dst port
            "0008"              # UDP length
            "0000"              # UDP checksum
        )

        while True:
            print("➡️  Inject packet to port 140 ...")
            self.interface.packet_push(raw_pkt, port=140)
            time.sleep(1)


    def cleanUp(self):
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
