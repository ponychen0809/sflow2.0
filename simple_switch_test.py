#!/usr/bin/env python3
import os
import json
import time
import threading

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP


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

        # ---------- NEW: auto-find counter table: port_in_bytes ----------
        self.port_in_bytes_tbl = self._find_table_by_contains("port_in_bytes")
        if self.port_in_bytes_tbl is None:
            # 如果你 P4 叫不同名字，這裡會直接中止，避免你以為有讀到
            raise RuntimeError("Cannot find counter table containing 'port_in_bytes' in BFRT")

        print("[FOUND] port_in_bytes counter table:", self.port_in_bytes_tbl.info.name_get())
        print("[port_in_bytes] key fields :", self.port_in_bytes_tbl.info.key_field_names_get())
        print("[port_in_bytes] data fields:", self.port_in_bytes_tbl.info.data_field_names_get())

        # ---------- NEW: optional match-action table to be updated (if exists) ----------
        # 你若有在 P4 加：
        # table MyIngress.if_stats_tbl { key: ig_intr_md.ingress_port; action set_if_stats(bit<64> ifInOctets); }
        # 這裡就會自動抓到並更新；沒有就略過
        self.if_stats_tbl = None
        try:
            self.if_stats_tbl = self.bfrt_info.table_get("MyIngress.if_stats_tbl")
            print("[FOUND] if_stats_tbl:", self.if_stats_tbl.info.name_get())
            print("[if_stats_tbl] key fields :", self.if_stats_tbl.info.key_field_names_get())
            print("[if_stats_tbl] data fields:", self.if_stats_tbl.info.data_field_names_get())
        except Exception:
            print("[INFO] MyIngress.if_stats_tbl not found (ok, will skip table update).")

        self.start_time = None
        self.cleanUp()

    # ----------------------------
    # BFRT helper: find table
    # ----------------------------
    def _find_table_by_contains(self, needle: str):
        needle = needle.lower().strip()
        try:
            table_names = list(self.bfrt_info.table_dict.keys())
        except Exception:
            # 部分版本沒有 table_dict
            try:
                table_names = self.bfrt_info.table_list_get()
            except Exception:
                table_names = []

        for name in table_names:
            if needle in name.lower():
                try:
                    return self.bfrt_info.table_get(name)
                except Exception:
                    pass
        return None

    # ----------------------------
    # BFRT helper: sync counter (so you read fresh value)
    # ----------------------------
    def _sync_counter_table(self, counter_tbl):
        # 不同版本 operation 名字不一樣，兩種都試
        for op in ("SyncCounters", "Sync"):
            try:
                counter_tbl.operations_execute(self.dev_tgt, op)
                return
            except Exception:
                continue

    # ----------------------------
    # NEW: read counter bytes (port_in_bytes)
    # ----------------------------
    def read_port_in_bytes(self, idx: int) -> int:
        """
        Read BYTES counter value for given index.
        idx = 你在 P4 內 port_in_bytes.count(idx) 的 idx
        """
        t = self.port_in_bytes_tbl

        # sync to get latest
        self._sync_counter_table(t)

        key_fields = t.info.key_field_names_get()
        if not key_fields:
            raise RuntimeError("port_in_bytes counter table has no key fields?")
        kf = key_fields[0]

        key = t.make_key([gc.KeyTuple(kf, int(idx))])

        # from_hw=True: 讀硬體值
        for data, _ in t.entry_get(self.dev_tgt, [key], {"from_hw": True}):
            d = data.to_dict()

            # 嘗試找 "bytes" 欄位
            for dk, dv in d.items():
                if "bytes" in dk.lower():
                    return int(dv)

            # 如果找不到，直接把 dict 印出來（方便你看欄位名）
            print("[read_port_in_bytes] Unexpected data dict:", d)
            raise RuntimeError("Cannot find a 'bytes' field in counter data dict")

        # 沒 entry 就回 0
        return 0

    # ----------------------------
    # NEW: update if_stats table if exists
    # ----------------------------
    def update_if_stats_if_exists(self, ingress_port: int, if_in_octets: int):
        """
        If MyIngress.if_stats_tbl exists, update it:
          key: ig_intr_md.ingress_port
          action: MyIngress.set_if_stats
          data: ifInOctets
        If not exists, do nothing.
        """
        if self.if_stats_tbl is None:
            return

        t = self.if_stats_tbl

        # 允許你用 config 覆蓋欄位/動作名字（不同 P4 你可能取不同名）
        upd_cfg = self.cfg.get("if_stats_update", {})
        key_name = upd_cfg.get("key", "ig_intr_md.ingress_port")
        action_name = upd_cfg.get("action", "MyIngress.set_if_stats")
        field_name = upd_cfg.get("field", "ifInOctets")

        key = t.make_key([gc.KeyTuple(key_name, int(ingress_port))])
        data = t.make_data([gc.DataTuple(field_name, int(if_in_octets))], action_name)

        # entry_mod 不存在會失敗 -> fallback entry_add
        try:
            t.entry_mod(self.dev_tgt, [key], [data])
        except Exception:
            t.entry_add(self.dev_tgt, [key], [data])

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
    # apply: mirror cfg
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

        test_cfg = self.cfg.get("test", {})
        send_port = int(test_cfg.get("send_port", 320))

        # 你要讀哪個 idx 的 counter（預設跟 send_port 一樣）
        # 注意：如果你的 P4 只在 140/143 count，那 counter_idx 要改成 140/143 或你要改 P4
        counter_idx = int(test_cfg.get("counter_idx", send_port))

        # 是否要把讀到的值回寫 table（如果 table 存在）
        enable_table_update = bool(test_cfg.get("enable_table_update", True))

        count = 0
        input(f"按 Enter 後開始每秒送封包到 PTF port {send_port}...\n")

        while True:
            count += 1

            # ---- BEFORE SEND: read counter ----
            try:
                before_bytes = self.read_port_in_bytes(counter_idx)
                print(f"[counter] BEFORE send: idx={counter_idx} bytes={before_bytes}")
            except Exception as e:
                before_bytes = None
                print(f"[counter] read error (idx={counter_idx}): {e}")

            # ---- BEFORE SEND: update table (optional) ----
            if enable_table_update and before_bytes is not None:
                try:
                    # 常見做法是用 ingress_port 當 key
                    self.update_if_stats_if_exists(counter_idx, before_bytes)
                    if self.if_stats_tbl is not None:
                        print(f"[if_stats_tbl] updated: port={counter_idx} ifInOctets={before_bytes}")
                except Exception as e:
                    print(f"[if_stats_tbl] update error: {e}")

            # ---- SEND ----
            print("{}, send_packet() to port {}".format(count, send_port))
            send_packet(self, send_port, pkt)

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
