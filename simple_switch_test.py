# simple_switch_test.py
import ptf
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xffff)

        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")
        self.tables = [self.ing_tbl]

        self.cleanUp()

    def runTest(self):
        # 建 key
        k1 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 140)]
        )
        k2 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 141)]
        )
        k3 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 142)]
        )
        k4 = self.ing_tbl.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", 143)]
        )

        # 建 data（對應 P4 的 action set_out_port(PortId_t port)）
        d1 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 141)],
            "MyIngress.set_out_port"
        )
        d2 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 140)],
            "MyIngress.set_out_port"
        )
        d3 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 143)],
            "MyIngress.set_out_port"
        )
        d4 = self.ing_tbl.make_data(
            [gc.DataTuple("port", 142)],
            "MyIngress.set_out_port"
        )

        # 一次加四條 entry
        self.ing_tbl.entry_add(
            self.dev_tgt,
            [k1, k2, k3, k4],
            [d1, d2, d3, d4]
        )

    def cleanUp(self):
        for t in self.tables:
            t.entry_del(self.dev_tgt, [])
            try:
                t.default_entry_reset(self.dev_tgt)
            except:
                pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
