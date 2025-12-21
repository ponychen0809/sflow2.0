#!/usr/bin/env python3
import os
import json
import time
import threading
import sys

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP


# ------------------------------------------------------------
# NEW: 讓 Python 2.7 的 input() 變成「讀字串」(不 eval)
# - 你後面照樣用 input("...") 不用改
# - 程式內不出現 raw_input
# ------------------------------------------------------------
try:
    import __builtin__  # Python2
    def _safe_input(prompt=""):
        try:
            sys.stdout.write(prompt)
            sys.stdout.flush()
        except Exception:
            pass
        line = sys.stdin.readline()
        if not line:
            return ""
        return line.rstrip("\n")
    __builtin__.input = _safe_input
except Exception:
    pass


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

        # ------------------------------------------------------------
        # NEW: 你要更新的 table + 你要讀的 counter
        # ------------------------------------------------------------
        self.if_stats_tbl = self.bfrt_info.table_get("MyIngress.if_stats_tbl")
        self.port_in_bytes_tbl = self.bfrt_info.table_get("MyIngress.port_in_bytes")

        # 你要讀/寫的 idx（可用 config 覆寫，不影響原本功能）
        bs = self.cfg.get("before_send_update", {})
        self.before_send_enable = bool(bs.get("enable", True))
        self.before_send_idx = int(bs.get("counter_idx", 140))

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

    # ------------------------------------------------------------
    # NEW: 讀 port_in_bytes counter (BYTES) & 更新 if_stats_tbl
    # ------------------------------------------------------------
    def _sync_counters_best_effort(self, tbl):
        # 不同版本可能叫不同 operation，逐個試
        for op in ["SyncCounters", "Sync", "sync_counters", "SyncHw", "SyncFromHw"]:
            try:
                tbl.operations_execute(self.dev_tgt, op)
                return
            except Exception:
                pass

    def read_port_in_bytes(self, idx):
        # sync (best effort)
        try:
            self._sync_counters_best_effort(self.port_in_bytes_tbl)
        except Exception as e:
            print("[counter] sync warning: {}".format(e))

        # key field name (取第一個)
        try:
            key_fields = self.port_in_bytes_tbl.info.key_field_names_get()
        except Exception as e:
            print("[counter] key_field_names_get Error: {}".format(e))
            key_fields = []

        if not key_fields:
            raise RuntimeError("counter table has no key field")

        key_name = key_fields[0]
        key = self.port_in_bytes_tbl.make_key([gc.KeyTuple(key_name, int(idx))])

        # 讀 entry
        try:
            it = self.port_in_bytes_tbl.entry_get(self.dev_tgt, [key], {"from_hw": True})
        except Exception:
            it = self.port_in_bytes_tbl.entry_get(self.dev_tgt, [key])

        for data, _ in it:
            d = data.to_dict()
            # 找 bytes 欄位
            for k, v in d.items():
                if "bytes" in str(k).lower():
                    try:
                        return long(v)  # py2
                    except Exception:
                        return int(v)
            raise RuntimeError("cannot find bytes field in counter data: {}".format(d))

        return 0

    def update_if_stats_tbl(self, ingress_port, ifInOctets):
        key = self.if_stats_tbl.make_key([
            gc.KeyTuple("ig_intr_md.ingress_port", int(ingress_port))
        ])

        data = self.if_stats_tbl.make_data([
            gc.DataTuple("ifInOctets", long(ifInOctets))
        ], "MyIngress.set_if_stats")

        try:
            try:
                self.if_stats_tbl.entry_mod(self.dev_tgt, [key], [data])
            except Exception:
                self.if_stats_tbl.entry_add(self.dev_tgt, [key], [data])

            print("[if_stats] updated: port={} ifInOctets={}".format(ingress_port, ifInOctets))
        except Exception as e:
            print("[if_stats] update Error: {}".format(e))

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
            # ----------------------------
            # NEW: 送封包前讀一次 + 更新 table
            # ----------------------------
            if self.before_send_enable:
                try:
                    idx = int(self.before_send_idx)
                    bytes_now = self.read_port_in_bytes(idx)
                    print("[counter] BEFORE send: idx={} bytes={}".format(idx, bytes_now))
                    self.update_if_stats_tbl(idx, bytes_now)
                except Exception as e:
                    print("[counter] read/update Error: {}".format(e))

            count += 1
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
