####### PTF / BFRuntime imports ########
import ptf
import grpc
import logging

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest


class SimpleSwitchTest(BfRuntimeTest):
    """
    啟用 dev port 140 / 141 / 142 / 143，
    並設定：
      MyIngress.ingress_port_forward:
        140 -> 141
        141 -> 140
        142 -> 143
        143 -> 142
      MyIngress.port_sampling_rate:
        ingress_port = 140, sampling_rate = 100
    """

    def setUp(self):
        self.client_id = 0
        # 這裡沿用原本檔案的寫法：用 test_param_get("simple_switch", "")
        # 如果你 run_p4_tests.sh 的 -p 參數改名了，再一起改。
        self.p4_name = ptf.testutils.test_param_get("simple_switch", "")
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # 建立與 switch 的連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 取得要操作的 tables
        self.port_table = self.bfrt_info.table_get("$PORT")
        self.ingress_port_forward = self.bfrt_info.table_get(
            "MyIngress.ingress_port_forward"
        )
        self.port_sampling_rate = self.bfrt_info.table_get(
            "MyIngress.port_sampling_rate"
        )

        # 之後 cleanUp 要把這些 table 清乾淨
        self.tables = [
            self.port_table,
            self.ingress_port_forward,
            self.port_sampling_rate,
        ]

        self.cleanUp()

    def runTest(self):
        self._enable_ports()
        self._program_ingress_port_forward()
        self._program_sampling_rate()

    # ---------------- internal helpers ----------------

    def _enable_ports(self):
        """用 $PORT table 開啟 dev port 140 / 141 / 142 / 143（10G, FEC NONE）"""
        ports = [140, 141, 142, 143]

        entry_keys = []
        for p in ports:
            entry_keys.append(
                self.port_table.make_key([
                    gc.KeyTuple("$DEV_PORT", p)
                ])
            )

        # 這邊參考原本 sample code 的設定：10G, FEC_NONE, 強制不 auto-negotiation, enable
        entry_data = self.port_table.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_10G"),
            gc.DataTuple("$FEC",   str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True),
        ])

        # 一次把四個 port 的設定寫進去
        self.port_table.entry_add(
            self.dev_tgt,
            entry_keys,
            [entry_data] * len(entry_keys),
        )

    def _program_ingress_port_forward(self):
        """
        寫 MyIngress.ingress_port_forward：
          140 -> 141
          141 -> 140
          142 -> 143
          143 -> 142
        對應 CLI：
          simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
              ingress_port=140, port=141)
          ...
        """
        rules = [
            (140, 141),
            (141, 140),
            (142, 143),
            (143, 142),
        ]

        keys = []
        datas = []
        for in_port, out_port in rules:
            # 注意欄位名稱要跟 P4 裡 table 的 key 一致
            # 你的 P4 是：key = { ig_intr_md.ingress_port : exact; }
            key = self.ingress_port_forward.make_key([
                gc.KeyTuple("ig_intr_md.ingress_port", in_port)
            ])
            data = self.ingress_port_forward.make_data(
                [gc.DataTuple("port", out_port)],
                "MyIngress.set_out_port"
            )
            keys.append(key)
            datas.append(data)

        self.ingress_port_forward.entry_add(
            self.dev_tgt,
            keys,
            datas,
        )

    def _program_sampling_rate(self):
        """
        寫 MyIngress.port_sampling_rate：
          ingress_port = 140, sampling_rate = 100
        對應 CLI：
          simple_switch.pipe.MyIngress.port_sampling_rate.add_with_set_sampling_rate(
              ingress_port=140, sampling_rate=100)
        """
        key = self.port_sampling_rate.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", 140)
        ])
        data = self.port_sampling_rate.make_data(
            [gc.DataTuple("sampling_rate", 100)],
            "MyIngress.set_sampling_rate",
        )

        self.port_sampling_rate.entry_add(
            self.dev_tgt,
            [key],
            [data],
        )

    # ---------------- clean up ----------------

    def cleanUp(self):
        """把我們用過的 tables 清乾淨（跟原 sample 一樣習慣）"""
        try:
            for t in self.tables:
                t.entry_del(self.dev_tgt, [])
                try:
                    t.default_entry_reset(self.dev_tgt)
                except Exception:
                    pass
        except Exception as e:
            print("Error cleaning up: {}".format(e))

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
