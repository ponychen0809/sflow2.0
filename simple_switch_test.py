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
        # 這裡直接寫程式名即可，跟你 run_p4_tests.sh -p simple_switch 對應
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # 0) port cfg table（用來做 port-add/port-enb）
        # 常見名字是 "$PORT"；如果你環境不同，改成你實際的 table name
        self.port_table = self.bfrt_info.table_get("$PORT")

        # 1) user forwarding table
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")

        # 2) sampling table
        self.port_sampling_tbl = self.bfrt_info.table_get("MyIngress.port_sampling_rate")

        # 3) port_agent table
        self.port_agent_tbl = self.bfrt_info.table_get("MyIngress.set_port_agent")

        # 4) PRE tables —— 名字是 $pre.node / $pre.mgid
        self.pre_node_tbl = self.bfrt_info.table_get("$pre.node")
        self.pre_mgid_tbl = self.bfrt_info.table_get("$pre.mgid")

        # 4.5) Mirror cfg table —— 你要新增的 mirror session rule 會寫這張表
        self.mirror_cfg_tbl = self.bfrt_info.table_get("$mirror.cfg")

        # 5) timestamp table（P4 裡要有 MyIngress.t_set_ts + action set_ts(ts)）
        #    table t_set_ts { key = { } actions = { set_ts; } size = 1; }
        self.ts_tbl = self.bfrt_info.table_get("MyIngress.t_set_ts")

        # 給 0 起點 timestamp 用的起始時間
        self.start_time = None

        self.cleanUp()

    def runTest(self):

        # ======== 記錄開始時間，之後 timestamp 會從 0 開始 ========
        self.start_time = time.time()

        # =========================================================
        # (0) Ports: port-add + port-enb
        # port-add 13/- 10G NONE
        # port-add 25/- 10G NONE
        # port-add 26/- 10G NONE
        # port-enb 13/-
        # port-enb 25/-
        # port-enb 26/-
        # （照你貼的 port_table.entry_add 範例寫法）
        # =========================================================
        try:
            entry_key_p13 = self.port_table.make_key([
                gc.KeyTuple('$DEV_PORT', 13)
            ])
            entry_key_p25 = self.port_table.make_key([
                gc.KeyTuple('$DEV_PORT', 25)
            ])
            entry_key_p26 = self.port_table.make_key([
                gc.KeyTuple('$DEV_PORT', 26)
            ])

            entry_data = self.port_table.make_data([
                gc.DataTuple("$SPEED", str_val="BF_SPEED_10G"),
                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                gc.DataTuple("$PORT_ENABLE", bool_val=True)
            ])

            self.port_table.entry_add(
                self.dev_tgt,
                [entry_key_p13, entry_key_p25, entry_key_p26],
                [entry_data, entry_data, entry_data]
            )
            print("Ports 13/25/26 已 port-add + port-enb (10G, NONE)")
        except Exception as e:
            print("Error on adding ports 13/25/26: {}".format(e))

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
        print("ingress_port_forward 規則已寫入")

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
        print("port_sampling_rate 規則已寫入")

        # =========================================================
        # (3) MyIngress.set_port_agent
        # =========================================================
        pa1_key = self.port_agent_tbl.make_key([
            gc.KeyTuple("hdr.sample.ingress_port", 140)
        ])
        pa1_data = self.port_agent_tbl.make_data(
            [
                gc.DataTuple("agent_addr", 0x0a0a0301),
                gc.DataTuple("agent_id", 1)
            ],
            "MyIngress.set_sample_hd"
        )

        pa2_key = self.port_agent_tbl.make_key([
            gc.KeyTuple("hdr.sample.ingress_port", 143)
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
        print("set_port_agent 規則已寫入")

        # =========================================================
        # (3.5) Mirror session: $mirror.cfg（照你指定的寫法）
        # sid=26, INGRESS, enable, mirror 到 dev_port=32, max_pkt_len=0
        # =========================================================
        try:
            self.mirror_cfg_tbl.entry_add(
                self.dev_tgt,
                [self.mirror_cfg_tbl.make_key([
                    gc.KeyTuple('$sid', 26)
                ])],
                [self.mirror_cfg_tbl.make_data([
                    gc.DataTuple('$direction', str_val='INGRESS'),
                    gc.DataTuple('$session_enable', bool_val=True),
                    gc.DataTuple('$ucast_egress_port', 32),
                    gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                    gc.DataTuple('$max_pkt_len', 0)
                ], '$normal')]
            )
            print("mirror cfg 已寫入:sid=26, INGRESS -> dev_port=32")
        except Exception as e:
            print("Error on adding mirror cfg: {}".format(e))

        # =========================================================
        # (4) PRE multicast: $pre.node / $pre.mgid
        # =========================================================
        node_id = 1
        dev_port_list = [32]   # device port 32 (ports.json map → PTF port 320)

        # ---- $pre.node ----
        try:
            self.pre_node_tbl.entry_add(
                self.dev_tgt,
                [self.pre_node_tbl.make_key([
                    gc.KeyTuple('$MULTICAST_NODE_ID', node_id)
                ])],
                [self.pre_node_tbl.make_data([
                    gc.DataTuple('$MULTICAST_RID', 1),
                    gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                    gc.DataTuple('$DEV_PORT', int_arr_val=dev_port_list)
                ])]
            )
            print("$pre.node 已寫入")
        except Exception as e:
            print("Error on adding $pre.node: {}".format(e))

        # ---- $pre.mgid ----
        mgid = 1
        try:
            self.pre_mgid_tbl.entry_add(
                self.dev_tgt,
                [self.pre_mgid_tbl.make_key([
                    gc.KeyTuple('$MGID', mgid)
                ])],
                [self.pre_mgid_tbl.make_data([
                    gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=[node_id]),
                    gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID',
                                 bool_arr_val=[False]),
                    gc.DataTuple('$MULTICAST_NODE_L1_XID',
                                 int_arr_val=[0])
                ])]
            )
            print("$pre.mgid 已寫入")
        except Exception as e:
            print("Error on adding $pre.mgid: {}".format(e))

        # =========================================================
        # (5) MyIngress.t_set_ts：先設 default entry = 0，
        #     之後每秒改成 0,1,2,3,...
        # =========================================================
        init_ts = 0
        ts_data = self.ts_tbl.make_data(
            [gc.DataTuple("ts", init_ts)],
            "MyIngress.set_ts"   # P4 action 名字
        )

        # 無 key table：用 default_entry_set 寫入
        self.ts_tbl.default_entry_set(
            self.dev_tgt,
            ts_data
        )
        print("t_set_ts 初始 timestamp = {} 已寫入".format(init_ts))

        # =========================================================
        # (6) 啟動背景 threads：
        #     - send_pkt_every_second：每秒送一包到 PTF port 320
        #     - update_ts_every_second：每秒更新一次 timestamp rule
        # =========================================================
        t1 = threading.Thread(target=self.send_pkt_every_second, daemon=True)
        t1.start()

        t2 = threading.Thread(target=self.update_ts_every_second, daemon=True)
        t2.start()

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

    # 每秒更新一次 timestamp rule（覆寫 default entry，從 0 開始累加）
    def update_ts_every_second(self):
        print("start upate timestamp")
        while True:
            # 從程式開始時間算起的經過秒數：0,1,2,3,...
            elapsed_sec = int(time.time() - self.start_time)

            ts_data = self.ts_tbl.make_data(
                [gc.DataTuple("ts", elapsed_sec)],
                "MyIngress.set_ts"
            )

            # 無 key table：一樣用 default_entry_set 覆蓋
            self.ts_tbl.default_entry_set(
                self.dev_tgt,
                ts_data
            )
            # print("更新 t_set_ts.ts = {}".format(elapsed_sec))
            time.sleep(1)

    def cleanUp(self):
        # 目前不清 table，避免把你其他設定刪掉
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
