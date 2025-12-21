#!/usr/bin/env python3
import os
import sys
import json
import time
import threading

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP


# ------------------------------------------------------------
# Keep using input() style, but make it safe for Python 2.7
# (Python2 built-in input() will eval and can throw SyntaxError)
# ------------------------------------------------------------
def input(prompt=""):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        return ""
    return line.rstrip("\n")


def _to_int(v):
    """Convert '0x..' string or int to int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        vv = v.strip().lower()
        if vv.startswith("0x"):
            return int(vv, 16)
        return int(vv)
    raise ValueError("Unsupported int value: {}".format(repr(v)))


class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "simple_switch"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # ---- load config ----
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.environ.get("SWITCH_CFG", os.path.join(script_dir, "config.json"))

        with open(cfg_path, "r") as f:
            self.cfg = json.load(f)

        print("[CFG] loaded: {}".format(cfg_path))

        # 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # system tables
        self.port_table = self.bfrt_info.table_get("$PORT")
        self.pre_node_tbl = self.bfrt_info.table_get("$pre.node")
        self.pre_mgid_tbl = self.bfrt_info.table_get("$pre.mgid")
        self.mirror_cfg_tbl = self.bfrt_info.table_get("$mirror.cfg")

        # p4 tables
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")
        self.port_sampling_tbl = self.bfrt_info.table_get("MyIngress.port_sampling_rate")
        self.port_agent_tbl = self.bfrt_info.table_get("MyIngress.set_port_agent")
        self.ts_tbl = self.bfrt_info.table_get("MyIngress.t_set_ts")

        # ---- NEW: counter + if_stats table (do not change other logic) ----
        self.port_in_bytes_tbl = self.bfrt_info.table_get("MyIngress.port_in_bytes")
        self.if_stats_tbl = self.bfrt_info.table_get("MyIngress.if_stats_tbl")

        self.start_time = None
        self.cleanUp()

    def runTest(self):
        self.start_time = time.time()

        self.apply_ports_from_cfg()
        self.apply_forwarding_from_cfg()
        self.apply_sampling_from_cfg()
        self.apply_port_agent_from_cfg()
        self.apply_mirror_cfg_from_cfg()
        self.apply_pre_from_cfg()
        self.apply_timestamp_from_cfg()

        # threads
        t1 = threading.Thread(target=self.send_pkt_every_second)
        t1.daemon = True
        t1.start()

        # 只有 timestamp.enable=true 才跑更新 thread
        if bool(self.cfg.get("timestamp", {}).get("enable", True)):
            t2 = threading.Thread(target=self.update_ts_every_second)
            t2.daemon = True
            t2.start()

        while True:
            time.sleep(1)

    # ----------------------------
    # NEW: read counter like CLI
    #   bfrt...MyIngress.port_in_bytes get(COUNTER_INDEX=140)
    #   key  : $COUNTER_INDEX
    #   data : $COUNTER_SPEC_BYTES
    # ----------------------------
    def read_port_in_bytes(self, counter_index):
        k = self.port_in_bytes_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_in_bytes_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_BYTES", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "bytes" in val:
                        return int(val.get("bytes", 0))
                    if "$COUNTER_SPEC_BYTES" in val:
                        return int(val.get("$COUNTER_SPEC_BYTES", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0

        # ----------------------------
    # NEW: write counter bytes into if_stats_tbl
    # - first time: entry_add
    # - after that: entry_mod (avoid "Already exists")
    # ----------------------------
    def update_if_stats_from_counter(self, ports):
        for p in ports:
            b = self.read_port_in_bytes(p)

            # ★ 每次讀到 counter 就印 index 與值
            print("[counter] index={} bytes={}".format(p, b))

            key = self.if_stats_tbl.make_key([
                gc.KeyTuple("ig_intr_md.ingress_port", int(p))
            ])
            data = self.if_stats_tbl.make_data(
                [gc.DataTuple("ifInOctets", int(b))],
                "MyIngress.set_if_stats"
            )

            wrote_ok = False

            # 先試著 mod
            try:
                self.if_stats_tbl.entry_mod(self.dev_tgt, [key], [data])
                wrote_ok = True
            except Exception as e_mod:
                print("[if_stats] entry_mod Error: {}".format(e_mod))

            # mod 不行才 add
            if not wrote_ok:
                try:
                    self.if_stats_tbl.entry_add(self.dev_tgt, [key], [data])
                    wrote_ok = True
                except Exception as e_add:
                    print("[if_stats] entry_add Error: {}".format(e_add))

            # ★ 新增：寫完立刻讀回來（不管成功與否都嘗試讀，方便 debug）
                    # ★ 新增：寫完立刻讀回來（從 HW 讀）
            try:
                it = self.if_stats_tbl.entry_get(self.dev_tgt, [key], {"from_hw": True})
                for d, k in it:
                    dd = d.to_dict()
                    # dd 可能長這樣: {'ifInOctets': 946, 'is_default_entry': False, 'action_name': 'MyIngress.set_if_stats'}
                    print("[if_stats] readback index={} data={}".format(p, dd))
                    break
            except Exception as e_rb:
                print("[if_stats] readback Error: {}".format(e_rb))



    # ----------------------------
    # apply: ports
    # ----------------------------
    def apply_ports_from_cfg(self):
        p = self.cfg.get("ports", {})
        ports = p.get("dev_ports", [])
        if not ports:
            print("[ports] skip (no dev_ports)")
            return

        speed = p.get("speed", "BF_SPEED_10G")
        fec = p.get("fec", "BF_FEC_TYP_NONE")
        autoneg = p.get("autoneg", "PM_AN_FORCE_DISABLE")
        enable = bool(p.get("enable", True))

        try:
            keys = [
                self.port_table.make_key([gc.KeyTuple("$DEV_PORT", int(dp))])
                for dp in ports
            ]

            data = self.port_table.make_data([
                gc.DataTuple("$SPEED", str_val=str(speed)),
                gc.DataTuple("$FEC", str_val=str(fec)),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val=str(autoneg)),
                gc.DataTuple("$PORT_ENABLE", bool_val=enable)
            ])

            self.port_table.entry_add(self.dev_tgt, keys, [data] * len(keys))
            print("[ports] added+enabled: {} (speed={}, fec={}, enable={})".format(
                ports, speed, fec, enable
            ))
        except Exception as e:
            print("[ports] Error: {}".format(e))

    # ----------------------------
    # apply: forwarding
    # ----------------------------
    def apply_forwarding_from_cfg(self):
        rules = self.cfg.get("forwarding", [])
        if not rules:
            print("[forwarding] skip (no rules)")
            return

        keys = []
        datas = []
        for r in rules:
            in_p = int(r["ingress_port"])
            out_p = int(r["egress_port"])
            keys.append(self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", in_p)]))
            datas.append(self.ing_tbl.make_data([gc.DataTuple("port", out_p)], "MyIngress.set_out_port"))

        try:
            self.ing_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[forwarding] rules written: {}".format(len(rules)))
        except Exception as e:
            print("[forwarding] Error: {}".format(e))

    # ----------------------------
    # apply: sampling rate
    # ----------------------------
    def apply_sampling_from_cfg(self):
        rules = self.cfg.get("sampling_rate", [])
        if not rules:
            print("[sampling] skip (no rules)")
            return

        keys = []
        datas = []
        for r in rules:
            in_p = int(r["ingress_port"])
            rate = int(r["rate"])
            keys.append(self.port_sampling_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", in_p)]))
            datas.append(self.port_sampling_tbl.make_data(
                [gc.DataTuple("sampling_rate", rate)],
                "MyIngress.set_sampling_rate"
            ))

        try:
            self.port_sampling_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[sampling] rules written: {}".format(len(rules)))
        except Exception as e:
            print("[sampling] Error: {}".format(e))

    # ----------------------------
    # apply: port agent (based on hdr.sample.ingress_port)
    # ----------------------------
    def apply_port_agent_from_cfg(self):
        rules = self.cfg.get("port_agent", [])
        if not rules:
            print("[port_agent] skip (no rules)")
            return

        keys = []
        datas = []
        for r in rules:
            in_p = int(r["ingress_port"])
            addr = _to_int(r["agent_addr"])
            agent_id = int(r["agent_id"])

            keys.append(self.port_agent_tbl.make_key([gc.KeyTuple("hdr.sample.ingress_port", in_p)]))
            datas.append(self.port_agent_tbl.make_data(
                [
                    gc.DataTuple("agent_addr", addr),
                    gc.DataTuple("agent_id", agent_id)
                ],
                "MyIngress.set_sample_hd"
            ))

        try:
            self.port_agent_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[port_agent] rules written: {}".format(len(rules)))
        except Exception as e:
            print("[port_agent] Error: {}".format(e))

    # ----------------------------
    # apply: mirror cfg (use your '$normal' style)
    # ----------------------------
    def apply_mirror_cfg_from_cfg(self):
        rules = self.cfg.get("mirror_cfg", [])
        if not rules:
            print("[mirror_cfg] skip (no rules)")
            return

        for r in rules:
            sid = r.get("sid")
            try:
                self.mirror_cfg_tbl.entry_add(
                    self.dev_tgt,
                    [self.mirror_cfg_tbl.make_key([
                        gc.KeyTuple("$sid", int(r["sid"]))
                    ])],
                    [self.mirror_cfg_tbl.make_data([
                        gc.DataTuple("$direction", str_val=str(r.get("direction", "INGRESS"))),
                        gc.DataTuple("$session_enable", bool_val=bool(r.get("session_enable", True))),
                        gc.DataTuple("$ucast_egress_port", int(r.get("ucast_egress_port", 0))),
                        gc.DataTuple("$ucast_egress_port_valid", bool_val=bool(r.get("ucast_egress_port_valid", True))),
                        gc.DataTuple("$max_pkt_len", int(r.get("max_pkt_len", 0)))
                    ], "$normal")]
                )
                print("[mirror_cfg] written: sid={} dir={} ucast={}".format(
                    r.get("sid"), r.get("direction"), r.get("ucast_egress_port")
                ))
            except Exception as e:
                print("[mirror_cfg] Error (sid={}): {}".format(sid, e))

    # ----------------------------
    # apply: PRE (optional)
    # ----------------------------
    def apply_pre_from_cfg(self):
        pre = self.cfg.get("pre", None)
        if not pre:
            print("[pre] skip (no config)")
            return

        node_id = int(pre.get("node_id", 1))
        mgid = int(pre.get("mgid", 1))
        rid = int(pre.get("rid", 1))
        dev_ports = [int(x) for x in pre.get("dev_ports", [])]

        if not dev_ports:
            print("[pre] skip (no dev_ports)")
            return

        # $pre.node
        try:
            self.pre_node_tbl.entry_add(
                self.dev_tgt,
                [self.pre_node_tbl.make_key([gc.KeyTuple("$MULTICAST_NODE_ID", node_id)])],
                [self.pre_node_tbl.make_data([
                    gc.DataTuple("$MULTICAST_RID", rid),
                    gc.DataTuple("$MULTICAST_LAG_ID", int_arr_val=[]),
                    gc.DataTuple("$DEV_PORT", int_arr_val=dev_ports)
                ])]
            )
            print("[pre.node] written: node_id={}, dev_ports={}".format(node_id, dev_ports))
        except Exception as e:
            print("[pre.node] Error: {}".format(e))

        # $pre.mgid
        try:
            self.pre_mgid_tbl.entry_add(
                self.dev_tgt,
                [self.pre_mgid_tbl.make_key([gc.KeyTuple("$MGID", mgid)])],
                [self.pre_mgid_tbl.make_data([
                    gc.DataTuple("$MULTICAST_NODE_ID", int_arr_val=[node_id]),
                    gc.DataTuple("$MULTICAST_NODE_L1_XID_VALID", bool_arr_val=[False]),
                    gc.DataTuple("$MULTICAST_NODE_L1_XID", int_arr_val=[0])
                ])]
            )
            print("[pre.mgid] written: mgid={} -> node_id={}".format(mgid, node_id))
        except Exception as e:
            print("[pre.mgid] Error: {}".format(e))

    # ----------------------------
    # apply: timestamp default entry
    # ----------------------------
    def apply_timestamp_from_cfg(self):
        ts_cfg = self.cfg.get("timestamp", {"enable": True, "init": 0})
        if not bool(ts_cfg.get("enable", True)):
            print("[timestamp] disabled by config")
            return

        init_ts = int(ts_cfg.get("init", 0))
        try:
            ts_data = self.ts_tbl.make_data([gc.DataTuple("ts", init_ts)], "MyIngress.set_ts")
            self.ts_tbl.default_entry_set(self.dev_tgt, ts_data)
            print("[timestamp] default init={}".format(init_ts))
        except Exception as e:
            print("[timestamp] Error: {}".format(e))

    # ----------------------------
    # threads
    # ----------------------------
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

            # ---- NEW: before send_packet, read counter then write into if_stats_tbl ----
            try:
                # default update ports = [140], you can override via config:
                #   "if_stats": {"ports":[140,143]}
                ports = self.cfg.get("if_stats", {}).get("ports", [140])
                self.update_if_stats_from_counter(ports)
            except Exception as e:
                print("[if_stats] read/update Error: {}".format(e))

            print("{}, send_packet() to port 320".format(count))
            send_packet(self, 320, pkt)
            time.sleep(1)

    def update_ts_every_second(self):
        print("[timestamp] start update thread")
        while True:
            elapsed_sec = int(time.time() - self.start_time)
            try:
                ts_data = self.ts_tbl.make_data([gc.DataTuple("ts", elapsed_sec)], "MyIngress.set_ts")
                self.ts_tbl.default_entry_set(self.dev_tgt, ts_data)
            except Exception as e:
                print("[timestamp] update Error: {}".format(e))
            time.sleep(1)

    def cleanUp(self):
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
