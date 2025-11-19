#!/usr/bin/env python3
import bfrt_grpc.client as gc

P4_NAME = "simple_switch"
GRPC_ADDR = "localhost:50052"
DEVICE_ID = 0

def main():
    # 連到 Tofino
    interface = gc.ClientInterface(
        grpc_addr=GRPC_ADDR,
        client_id=0,
        device_id=DEVICE_ID,
        is_master=True
    )

    # 綁定 pipeline
    interface.bind_pipeline_config(p4_name=P4_NAME)

    # 拿 bfrt_info
    bfrt_info = interface.bfrt_info_get(P4_NAME)

    # 取得 table 物件
    ingress_port_forward = bfrt_info.table_get("MyIngress.ingress_port_forward")
    port_sampling_rate   = bfrt_info.table_get("MyIngress.port_sampling_rate")

    # 目標：所有 pipe
    target = gc.Target(device_id=DEVICE_ID, pipe_id=0xffff)

    # ---------- 填 ingress_port_forward ----------
    def add_ingress_port_forward(in_port, out_port):
        key = ingress_port_forward.make_key([
            gc.KeyTuple('ig_intr_md.ingress_port', in_port)
        ])
        data = ingress_port_forward.make_data(
            [gc.DataTuple('port', out_port)],
            'MyIngress.set_out_port'      # action 名稱
        )
        ingress_port_forward.entry_add(target, [key], [data])

    add_ingress_port_forward(140, 141)
    add_ingress_port_forward(141, 140)
    add_ingress_port_forward(142, 143)
    add_ingress_port_forward(143, 142)

    # ---------- 填 port_sampling_rate ----------
    def add_port_sampling_rate(in_port, rate):
        key = port_sampling_rate.make_key([
            gc.KeyTuple('ig_intr_md.ingress_port', in_port)
        ])
        data = port_sampling_rate.make_data(
            [gc.DataTuple('sampling_rate', rate)],
            'MyIngress.set_sampling_rate'  # action 名稱
        )
        port_sampling_rate.entry_add(target, [key], [data])

    add_port_sampling_rate(140, 100)

    print("Programming done.")

if __name__ == "__main__":
    main()
