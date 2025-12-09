import struct
import os
import sys

from scapy.all import sniff

# ------------------------------
# Basic helpers
# ------------------------------
def read_u32(raw, offset):
    """讀取 4 bytes big-endian，回傳(value, 新offset)。"""
    if offset + 4 > len(raw):
        return None, offset  # 安全防呆
    val = struct.unpack("!I", raw[offset:offset+4])[0]
    return val, offset+4


def detect_ipv4_offset(raw):
    """
    嘗試偵測 IPv4 header 在封包中的 offset。

    1) Linux cooked capture (SLL)：前 20 bytes 是 SLL header，IPv4 通常從 20 開始，
       第一個 byte 類似 0x45 (version=4, IHL=5)。
    2) Ethernet II：前 14 bytes 是 Ethernet header，
       byte[12:14] = 0x0800 表示 IPv4，IPv4 從 14 開始。
    """
    # Linux SLL
    if len(raw) > 21 and (raw[20] >> 4) == 4:
        return 20

    # Ethernet II
    if len(raw) > 14 and raw[12] == 0x08 and raw[13] == 0x00 and (raw[14] >> 4) == 4:
        return 14

    return None


# ------------------------------
# IPv4
# ------------------------------
def parse_ipv4_header(raw, offset):
    base = offset
    ver_ihl = raw[offset]
    ihl = (ver_ihl & 0x0F) * 4
    proto = raw[offset+9]

    src = ".".join(map(str, raw[offset+12:offset+16]))
    dst = ".".join(map(str, raw[offset+16:offset+20]))

    print(f"[IPv4 @ {base}]")
    print(f"  [{base}] version_ihl = 0x{ver_ihl:02x}")
    print(f"  [{base+9}] proto       = {proto}")
    print(f"  [{base+12}-{base+15}] src         = {src}")
    print(f"  [{base+16}-{base+19}] dst         = {dst}")

    return ihl, proto


# ------------------------------
# UDP
# ------------------------------
def parse_udp_header(raw, offset):
    base = offset
    if offset + 8 > len(raw):
        print("UDP header truncated")
        return 0, 0
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[offset:offset+8])

    print(f"[UDP @ {base}]")
    print(f"  [{base}-{base+1}] src_port = {src_port}")
    print(f"  [{base+2}-{base+3}] dst_port = {dst_port}")
    print(f"  [{base+4}-{base+5}] length   = {length}")

    return 8, dst_port


# ------------------------------
# Record Parser (Flow record = type 1)
# ------------------------------
def parse_raw_header_record(raw, offset):
    """
    解析 Flow Record 裡的 Raw Packet Header (record_type=1)。
    其它 record_type 先只 dump 十六進位。
    """
    base = offset
    if offset + 8 > len(raw):
        print(f"\n    [Record @ {base}]  **TRUNCATED HEADER**")
        return len(raw)

    rt_off = offset
    record_type, offset = read_u32(raw, offset)
    len_off = offset
    length, offset = read_u32(raw, offset)

    print(f"\n    [Record @ {base}]")
    print(f"      [{rt_off}-{rt_off+3}] record_type = {record_type}")
    print(f"      [{len_off}-{len_off+3}] length      = {length}")

    end = offset + length
    if end > len(raw):
        print(f"      **TRUNCATED DATA** expected {length}, available {len(raw)-offset}")
        data = raw[offset:]
        print(f"      [{offset}-{offset+len(data)-1}] raw_header ({len(data)} bytes): {data.hex(' ')}")
        return len(raw)

    data = raw[offset:end]
    print(f"      [{offset}-{end-1}] raw_header ({len(data)} bytes): {data.hex(' ')}")

    # 只對 Raw Packet Header 做進一步解析
    if record_type == 1:
        if len(data) < 16:
            print("      (data too short for Raw Packet Header)")
            return end

        data_base = offset  # 在 flow sample 裡的起點

        # sFlow Raw Packet Header 結構：
        #   0–3 : header_protocol
        #   4–7 : frame_length
        #   8–11: payload_removed
        #   12–15: header_length
        header_protocol = struct.unpack("!I", data[0:4])[0]
        frame_length    = struct.unpack("!I", data[4:8])[0]
        payload_removed = struct.unpack("!I", data[8:12])[0]
        header_length   = struct.unpack("!I", data[12:16])[0]

        print("      --- Decoded Raw Packet Header ---")
        print(f"      [{data_base+0}-{data_base+3}]   header_protocol = {header_protocol}  (1 = ethernet)")
        print(f"      [{data_base+4}-{data_base+7}]   frame_length    = {frame_length}")
        print(f"      [{data_base+8}-{data_base+11}]  payload_removed = {payload_removed}")
        print(f"      [{data_base+12}-{data_base+15}] header_length   = {header_length}")

        hb_start = data_base + 16
        header_bytes = data[16:16+header_length]
        print(f"      [{hb_start}-{hb_start+len(header_bytes)-1}] header_bytes ({len(header_bytes)} bytes)")

        # 進一步把 header_bytes 當成乙太封包再解一次
        if len(header_bytes) >= 14:
            dst_mac = ":".join(f"{b:02x}" for b in header_bytes[0:6])
            src_mac = ":".join(f"{b:02x}" for b in header_bytes[6:12])
            eth_type = (header_bytes[12] << 8) | header_bytes[13]

            print("      [Inner Ethernet]")
            print(f"        [{hb_start+0}-{hb_start+5}]  dst_mac  = {dst_mac}")
            print(f"        [{hb_start+6}-{hb_start+11}] src_mac  = {src_mac}")
            print(f"        [{hb_start+12}-{hb_start+13}] eth_type = 0x{eth_type:04x}")

            # 如果是 IPv4 再往下拆
            if eth_type == 0x0800 and len(header_bytes) >= 34:
                ipv4_off  = 14
                ipv4_base = hb_start + ipv4_off
                ver_ihl   = header_bytes[ipv4_off]
                ihl       = (ver_ihl & 0x0F) * 4
                proto     = header_bytes[ipv4_off + 9]
                src_ip    = ".".join(map(str, header_bytes[ipv4_off+12:ipv4_off+16]))
                dst_ip    = ".".join(map(str, header_bytes[ipv4_off+16:ipv4_off+20]))

                print("      [Inner IPv4]")
                print(f"        [{ipv4_base}] version_ihl = 0x{ver_ihl:02x}")
                print(f"        [{ipv4_base+9}] proto       = {proto}")
                print(f"        [{ipv4_base+12}-{ipv4_base+15}] src_ip      = {src_ip}")
                print(f"        [{ipv4_base+16}-{ipv4_base+19}] dst_ip      = {dst_ip}")

                l4_off = ipv4_off + ihl
                l4_base = hb_start + l4_off

                # UDP
                if proto == 17 and len(header_bytes) >= l4_off + 8:
                    src_port, dst_port, length, cksum = struct.unpack(
                        "!HHHH", header_bytes[l4_off:l4_off+8]
                    )
                    print("      [Inner UDP]")
                    print(f"        [{l4_base}-{l4_base+1}] src_port = {src_port}")
                    print(f"        [{l4_base+2}-{l4_base+3}] dst_port = {dst_port}")
                    print(f"        [{l4_base+4}-{l4_base+5}] length   = {length}")
                # TCP (只簡單印 port)
                elif proto == 6 and len(header_bytes) >= l4_off + 4:
                    src_port, dst_port = struct.unpack(
                        "!HH", header_bytes[l4_off:l4_off+4]
                    )
                    print("      [Inner TCP]")
                    print(f"        [{l4_base}-{l4_base+1}] src_port = {src_port}")
                    print(f"        [{l4_base+2}-{l4_base+3}] dst_port = {dst_port}")

    return end


# ------------------------------
# Counter Sample Parser (Type 2 / 4)
# ------------------------------
def parse_counter_sample(raw, offset):
    """
    用於解析：
      - type = 2  Counter Sample
      - type = 4  Expanded Counter Sample (目前當一般 Counter Sample 看，頭一樣先 seq/source_id/rec_count)

    並且對常見的 counter record：
      - rec_type = 1 → ifCounters
      - rec_type = 2 → ethernetCounters
    做欄位級解析。
    """
    base = offset
    print(f"\n----- Counter Sample @ {base} -----")

    seq_off = offset
    seq, offset = read_u32(raw, offset)
    sid_off = offset
    source_id, offset = read_u32(raw, offset)

    print(f"  [{seq_off}-{seq_off+3}] seq   = {seq}")
    print(f"  [{sid_off}-{sid_off+3}] source_id = {source_id}")

    rc_off = offset
    rec_count, offset = read_u32(raw, offset)
    print(f"  [{rc_off}-{rc_off+3}] counter_record_count = {rec_count}")

    for i in range(rec_count):
        print(f"  ---- Counter Record #{i+1} ----")

        if offset + 8 > len(raw):
            print("  **TRUNCATED counter record header**")
            return len(raw)

        rt_off = offset
        rec_type, offset = read_u32(raw, offset)
        rl_off = offset
        rec_len, offset = read_u32(raw, offset)

        print(f"    [{rt_off}-{rt_off+3}] type   = {rec_type}")
        print(f"    [{rl_off}-{rl_off+3}] length = {rec_len}")

        end = offset + rec_len
        if end > len(raw):
            print("    **TRUNCATED counter record data**")
            data = raw[offset:]
            print(f"    [{offset}-{offset+len(data)-1}] data: {data.hex(' ')}")
            return len(raw)

        data = raw[offset:end]
        data_base = offset

        # --------- ifCounters ----------
        if rec_type == 1 and rec_len >= 88:
            print("    --- Decoded Generic Interface Counters (ifCounters) ---")
            (
                ifIndex,
                ifType,
                ifSpeed,
                ifDirection,
                ifStatus,
                ifInOctets,
                ifInUcastPkts,
                ifInMulticastPkts,
                ifInBroadcastPkts,
                ifInDiscards,
                ifInErrors,
                ifInUnknownProtos,
                ifOutOctets,
                ifOutUcastPkts,
                ifOutMulticastPkts,
                ifOutBroadcastPkts,
                ifOutDiscards,
                ifOutErrors,
                ifPromiscuousMode,
            ) = struct.unpack("!IIQIIQIIIIIIQIIIIII", data[:88])

            o = data_base
            print(f"    [{o+0}-{o+3}]   ifIndex            = {ifIndex}")
            print(f"    [{o+4}-{o+7}]   ifType             = {ifType}")
            print(f"    [{o+8}-{o+15}]  ifSpeed            = {ifSpeed}")
            print(f"    [{o+16}-{o+19}] ifDirection        = {ifDirection}")
            print(f"    [{o+20}-{o+23}] ifStatus           = {ifStatus}")
            print(f"    [{o+24}-{o+31}] ifInOctets         = {ifInOctets}")
            print(f"    [{o+32}-{o+35}] ifInUcastPkts      = {ifInUcastPkts}")
            print(f"    [{o+36}-{o+39}] ifInMulticastPkts  = {ifInMulticastPkts}")
            print(f"    [{o+40}-{o+43}] ifInBroadcastPkts  = {ifInBroadcastPkts}")
            print(f"    [{o+44}-{o+47}] ifInDiscards       = {ifInDiscards}")
            print(f"    [{o+48}-{o+51}] ifInErrors         = {ifInErrors}")
            print(f"    [{o+52}-{o+55}] ifInUnknownProtos  = {ifInUnknownProtos}")
            print(f"    [{o+56}-{o+63}] ifOutOctets        = {ifOutOctets}")
            print(f"    [{o+64}-{o+67}] ifOutUcastPkts     = {ifOutUcastPkts}")
            print(f"    [{o+68}-{o+71}] ifOutMulticastPkts = {ifOutMulticastPkts}")
            print(f"    [{o+72}-{o+75}] ifOutBroadcastPkts = {ifOutBroadcastPkts}")
            print(f"    [{o+76}-{o+79}] ifOutDiscards      = {ifOutDiscards}")
            print(f"    [{o+80}-{o+83}] ifOutErrors        = {ifOutErrors}")
            print(f"    [{o+84}-{o+87}] ifPromiscuousMode  = {ifPromiscuousMode}")

            if rec_len > 88:
                extra = data[88:]
                print(f"    [{data_base+88}-{data_base+rec_len-1}] extra_data ({len(extra)} bytes): {extra.hex(' ')}")

        # --------- ethernetCounters ----------
        elif rec_type == 2 and rec_len >= 52:
            print("    --- Decoded Ethernet Counters (dot3Stats) ---")
            (
                alignmentErrors,
                fcsErrors,
                singleCollisionFrames,
                multipleCollisionFrames,
                sqeTestErrors,
                deferredTransmissions,
                lateCollisions,
                excessiveCollisions,
                internalMacTransmitErrors,
                carrierSenseErrors,
                frameTooLongs,
                internalMacReceiveErrors,
                symbolErrors,
            ) = struct.unpack("!IIIIIIIIIIIII", data[:52])

            o = data_base
            print(f"    [{o+0}-{o+3}]   dot3StatsAlignmentErrors         = {alignmentErrors}")
            print(f"    [{o+4}-{o+7}]   dot3StatsFCSErrors               = {fcsErrors}")
            print(f"    [{o+8}-{o+11}]  dot3StatsSingleCollisionFrames   = {singleCollisionFrames}")
            print(f"    [{o+12}-{o+15}] dot3StatsMultipleCollisionFrames = {multipleCollisionFrames}")
            print(f"    [{o+16}-{o+19}] dot3StatsSQETestErrors           = {sqeTestErrors}")
            print(f"    [{o+20}-{o+23}] dot3StatsDeferredTransmissions   = {deferredTransmissions}")
            print(f"    [{o+24}-{o+27}] dot3StatsLateCollisions          = {lateCollisions}")
            print(f"    [{o+28}-{o+31}] dot3StatsExcessiveCollisions     = {excessiveCollisions}")
            print(f"    [{o+32}-{o+35}] dot3StatsInternalMacTxErrors     = {internalMacTransmitErrors}")
            print(f"    [{o+36}-{o+39}] dot3StatsCarrierSenseErrors      = {carrierSenseErrors}")
            print(f"    [{o+40}-{o+43}] dot3StatsFrameTooLongs           = {frameTooLongs}")
            print(f"    [{o+44}-{o+47}] dot3StatsInternalMacRxErrors     = {internalMacReceiveErrors}")
            print(f"    [{o+48}-{o+51}] dot3StatsSymbolErrors            = {symbolErrors}")

            if rec_len > 52:
                extra = data[52:]
                print(f"    [{data_base+52}-{data_base+rec_len-1}] extra_data ({len(extra)} bytes): {extra.hex(' ')}")

        else:
            print(f"    [{data_base}-{data_base+rec_len-1}] data: {data.hex(' ')}")

        offset = end

    return offset


# ------------------------------
# Flow Sample Parser (Type 1)
# ------------------------------
def parse_flow_sample(raw, offset):
    """普通 Flow Sample (type=1)。"""
    base = offset
    print(f"\n----- Flow Sample @ {base} -----")

    seq_off = offset
    seq, offset = read_u32(raw, offset)
    sid_off = offset
    source_id, offset = read_u32(raw, offset)
    rate_off = offset
    rate, offset = read_u32(raw, offset)
    pool_off = offset
    pool, offset = read_u32(raw, offset)
    drops_off = offset
    drops, offset = read_u32(raw, offset)
    in_off = offset
    in_if, offset = read_u32(raw, offset)
    out_off = offset
    out_if, offset = read_u32(raw, offset)
    rc_off = offset
    rec_count, offset = read_u32(raw, offset)

    print(f"  [{seq_off}-{seq_off+3}]   seq           = {seq}")
    print(f"  [{sid_off}-{sid_off+3}]   source_id     = {source_id}")
    print(f"  [{rate_off}-{rate_off+3}] sampling_rate = {rate}")
    print(f"  [{pool_off}-{pool_off+3}] sample_pool   = {pool}")
    print(f"  [{drops_off}-{drops_off+3}] drops         = {drops}")
    print(f"  [{in_off}-{in_off+3}]   input_if      = {in_if}")
    print(f"  [{out_off}-{out_off+3}]  output_if     = {out_if}")
    print(f"  [{rc_off}-{rc_off+3}]   record_count  = {rec_count}")

    for i in range(rec_count):
        print(f"\n  ---- Record #{i+1} ----")
        offset = parse_raw_header_record(raw, offset)

    return offset


# ------------------------------
# Expanded Flow Sample Parser (Type 3)
# ------------------------------
def parse_expanded_flow_sample(raw, offset):
    base = offset
    print(f"\n----- Expanded Flow Sample @ {base} -----")

    seq_off = offset
    seq, offset = read_u32(raw, offset)
    st_off = offset
    src_type, offset = read_u32(raw, offset)
    si_off = offset
    src_index, offset = read_u32(raw, offset)
    rate_off = offset
    rate, offset = read_u32(raw, offset)
    pool_off = offset
    pool, offset = read_u32(raw, offset)
    drops_off = offset
    drops, offset = read_u32(raw, offset)
    in_fmt_off = offset
    in_fmt, offset = read_u32(raw, offset)
    in_val_off = offset
    in_val, offset = read_u32(raw, offset)
    out_fmt_off = offset
    out_fmt, offset = read_u32(raw, offset)
    out_val_off = offset
    out_val, offset = read_u32(raw, offset)
    rc_off = offset
    rec_count, offset = read_u32(raw, offset)

    print(f"  [{seq_off}-{seq_off+3}]   seq              = {seq}")
    print(f"  [{st_off}-{st_off+3}]   source_id_type   = {src_type}")
    print(f"  [{si_off}-{si_off+3}]   source_id_index  = {src_index}")
    print(f"  [{rate_off}-{rate_off+3}] sampling_rate    = {rate}")
    print(f"  [{pool_off}-{pool_off+3}] sample_pool      = {pool}")
    print(f"  [{drops_off}-{drops_off+3}] drops            = {drops}")
    print(f"  [{in_fmt_off}-{in_fmt_off+3}]  input_if_format  = {in_fmt}")
    print(f"  [{in_val_off}-{in_val_off+3}]  input_if_value   = {in_val}")
    print(f"  [{out_fmt_off}-{out_fmt_off+3}] output_if_format = {out_fmt}")
    print(f"  [{out_val_off}-{out_val_off+3}] output_if_value  = {out_val}")
    print(f"  [{rc_off}-{rc_off+3}]   record_count     = {rec_count}")

    for i in range(rec_count):
        print(f"\n  ---- Record #{i+1} ----")
        offset = parse_raw_header_record(raw, offset)

    return offset


# ------------------------------
# sFlow Main Parser
# ------------------------------
def parse_sflow(raw):
    offset = 0
    base = offset
    v_off = offset
    version, offset = read_u32(raw, offset)
    if version != 5:
        print("Not sFlow v5")
        return [], offset

    at_off = offset
    agent_type, offset = read_u32(raw, offset)

    print(f"\n===== [sFlow @ {base}] =====")
    print(f"  [{v_off}-{v_off+3}]  version          = {version}")
    print(f"  [{at_off}-{at_off+3}] agent_addr_type  = {agent_type}")

    if agent_type == 1:
        ip_off = offset
        ip = ".".join(map(str, raw[offset:offset+4]))
        print(f"  [{ip_off}-{ip_off+3}] agent_ip         = {ip}")
        offset += 4
    else:
        offset += 4

    sa_off = offset
    sub_agent, offset = read_u32(raw, offset)
    seq_off = offset
    seq, offset = read_u32(raw, offset)
    up_off = offset
    uptime, offset = read_u32(raw, offset)
    sc_off = offset
    sample_count, offset = read_u32(raw, offset)

    print(f"  [{sa_off}-{sa_off+3}] sub_agent        = {sub_agent}")
    print(f"  [{seq_off}-{seq_off+3}] sequence         = {seq}")
    print(f"  [{up_off}-{up_off+3}] uptime           = {uptime}")
    print(f"  [{sc_off}-{sc_off+3}] sample_count     = {sample_count}")

    sample_types = []

    for i in range(sample_count):
        if offset + 8 > len(raw):
            print("** TRUNCATED sample header **")
            break

        st_off = offset
        sample_type, offset = read_u32(raw, offset)
        sl_off = offset
        sample_len, offset = read_u32(raw, offset)

        print(f"\nSample #{i+1}:")
        print(f"  [{st_off}-{st_off+3}] type = {sample_type}")
        print(f"  [{sl_off}-{sl_off+3}] len  = {sample_len}")
        sample_body = raw[offset:offset+sample_len]

        sample_types.append(sample_type)

        if offset + sample_len > len(raw):
            print("** TRUNCATED sample body **")
            break

        if sample_type == 1:
            parse_flow_sample(sample_body, 0)
        elif sample_type == 3:
            parse_expanded_flow_sample(sample_body, 0)
        elif sample_type in (2, 4):
            parse_counter_sample(sample_body, 0)
        else:
            print(f"Unknown sample type {sample_type}")

        offset += sample_len

    return sample_types, offset


# ------------------------------
# 單一封包解析（共用）
# ------------------------------
packet_counter = 0

def handle_raw_frame(raw):
    """
    直接給一個完整的 L2 frame / SLL frame，
    走跟原本 parse_pcap 內一樣的解析流程，但改成直接印。
    """
    global packet_counter
    packet_counter += 1
    pkt_id = packet_counter

    print(f"\n===== Packet #{pkt_id} =====")
    print("RAW first 64 bytes:", raw[:64].hex(" "))

    ipv4_offset = detect_ipv4_offset(raw)

    if ipv4_offset is None:
        print("IPv4 not found or unsupported link type")
        return

    ihl, proto = parse_ipv4_header(raw, ipv4_offset)
    offset = ipv4_offset + ihl

    udp_len, dst_port = parse_udp_header(raw, offset)
    offset += udp_len

    if dst_port == 6343:
        parse_sflow(raw[offset:])
    else:
        print("Not sFlow UDP (dst_port != 6343)")


# ------------------------------
# Live Capture (scapy)
# ------------------------------
def scapy_callback(pkt):
    """
    sniff() 收到封包後的 callback。
    已經用 BPF filter 過 'udp port 6343'，
    所以這裡直接轉成 raw bytes 丟給解析器。
    """
    raw = bytes(pkt.original) if hasattr(pkt, "original") else bytes(pkt)
    handle_raw_frame(raw)


def live_capture(iface="any"):
    """
    直接監聽某個網卡，只抓 UDP port 6343。
    """
    print(f"Start sniffing on interface '{iface}' (udp port 6343)...")
    print("Press Ctrl+C to stop.\n")
    sniff(iface=iface, filter="udp port 6343", prn=scapy_callback, store=0)


if __name__ == "__main__":
    # 介面名稱從命令列參數帶入，沒給就用 "any"
    iface = sys.argv[1] if len(sys.argv) > 1 else "any"
    live_capture(iface)
