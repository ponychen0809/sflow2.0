####### PTF & BFRT IMPORTS ########
import ptf
from ptf.testutils import *

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest


class SimpleTableTest(BfRuntimeTest):
    """
    最簡單版本：
    - 連到 simple_switch
    - 操作 MyIngress.ingress_port_forward table
    - 下 4 條 rule：
        140 -> 141
        141 -> 140
        142 -> 143
        143 -> 142
    """

    def setUp(self):
        # basic 參數
        self.client_id = 0
        self.dev = 0
        self.p4_name = "simple_switch"   # 對應你編出的 p4 名字
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xffff)

        # 建立與 switchd / BFRT 的連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 取得想要操作的 table
        self.fwd_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")

        # （可選）告訴 BFRT 這個欄位是 port 型別，比較好看
        self.fwd_tbl.info.key_field_annotation_add(
            "ig_intr_md.ingress_port", "port"
        )

        # 先清掉舊資料
        self.cleanUp()

    def runTest(self):
        # === 1. 準備 key ===
        k_140 = self.fwd_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 140)
        ])
        k_141 = self.fwd_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 141)
        ])
        k_142 = self.fwd_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 142)
        ])
        k_143 = self.fwd_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 143)
        ])

        # === 2. 準備 data（對應 set_out_port action 的參數 port）===
        d_140_to_141 = self.fwd_tbl.make_data(
            [gc.DataTuple("port", 141)],
            "MyIngress.set_out_port"
        )
        d_141_to_140 = self.fwd_tbl.make_data(
            [gc.DataTuple("port", 140)],
            "MyIngress.set_out_port"
        )
        d_142_to_143 = self.fwd_tbl.make_data(
            [gc.DataTuple("port", 143)],
            "MyIngress.set_out_port"
        )
        d_143_to_142 = self.fwd_tbl.make_data(
            [gc.DataTuple("port", 142)],
            "MyIngress.set_out_port"
        )

        # === 3. 一次把 4 條 rule 加進去 ===
        self.fwd_tbl.entry_add(
            self.dev_tgt,
            [k_140, k_141, k_142, k_143],
            [d_140_to_141, d_141_to_140, d_142_to_143, d_143_to_142],
        )

        print("✅ 已經對 MyIngress.ingress_port_forward 下好 4 條 rule 了")

    # ------------------------------------------------------------------
    # 清 table 的工具函式（跟你原本的 cleanUp 很像，只針對這一張 table）
    # ------------------------------------------------------------------
    def cleanUp(self):
        try:
            self.fwd_tbl.entry_del(self.dev_tgt, [])
            try:
                self.fwd_tbl.default_entry_reset(self.dev_tgt)
            except Exception:
                pass
        except Exception as e:
            print("Error cleaning up ingress_port_forward: {}".format(e))

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
