# simple_switch_test.py
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest


class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        # 固定寫就好
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # 跟 switchd 建立 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)

        # 拿到 bfrt 資訊
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 這個名字要跟你 P4 裡的 table 名字一模一樣
        # 例如：table ingress_port_forward { ... } 在 MyIngress 裡
        self.ing_tbl = self.bfrt_info.table_get(
            "MyIngress.ingress_port_forward"
        )

        # 之後 cleanUp 用
        self.tables = [self.ing_tbl]

        # 先把舊的 entry 清掉
        self.cleanUp()

    def runTest(self):
        # === 這裡開始就是你真正要下 rule 的地方 ===
        # key 欄位名稱要跟 P4 裡寫的一樣：例如 key = { ig_intr_md.ingress_port : exact; }

        k1 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 140)]
        )
        d1 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 141)],   # 對應 action set_out_port(PortId_t port)
            "MyIngress.set_out_port"
        )

        k2 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 141)]
        )
        d2 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 140)],
            "MyIngress.set_out_port"
        )

        k3 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 142)]
        )
        d3 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 143)],
            "MyIngress.set_out_port"
        )

        k4 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 143)]
        )
        d4 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 142)],
            "MyIngress.set_out_port"
        )

        # 一次把四條 rule 加進去
        self.ing_tbl.entry_add(
            self.dev_tgt,
            [k1, k2, k3, k4],
            [d1, d2, d3, d4]
        )

        print("✅ ingress_port_forward 規則已寫入完成")

    def cleanUp(self):
        # 把這個 test 裡管到的 tables 清空
        for t in self.tables:
            t.entry_del(self.dev_tgt, [])
            try:
                t.default_entry_reset(self.dev_tgt)
            except Exception:
                pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
