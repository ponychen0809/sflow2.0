# config_simple_switch.py

# 這個 bfrt 物件是 bfshell 幫你準備好的
p4 = bfrt.simple_switch

# 之後都用 p4 來操作
p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=140, port=141)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=141, port=140)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=142, port=143)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=143, port=142)

p4.pipe.MyIngress.port_sampling_rate.add_with_set_sampling_rate(
    ingress_port=140, sampling_rate=100)

print(">>> simple_switch config done.")
