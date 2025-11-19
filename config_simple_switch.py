# config_simple_switch.py

# 這個 bfrt 物件是 bfshell 幫你準備好的
p4 = bfrt.simple_switch
p4_pre = bfrt.pre
# 之後都用 p4 來操作
p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=140, port=141)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=141, port=140)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=142, port=143)

p4.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=143, port=142)

p4.pipe.MyIngress.port_sampling_rate.add_with_set_sampling_rate(ingress_port=140, sampling_rate=100)
p4.pipe.MyIngress.port_sampling_rate.add_with_set_sampling_rate(ingress_port=140, sampling_rate=50)
p4_pre.node.add(DEV_PORT=[32], MULTICAST_LAG_ID=[], MULTICAST_NODE_ID=1, MULTICAST_RID=1)

p4_pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[1], MULTICAST_NODE_L1_XID=[0], MULTICAST_NODE_L1_XID_VALID=[0])

p4.pipe.MyIngress.set_port_agent.add_with_set_sample_hd(ingress_port=140,agent_addr=0x0a0a0301,agent_id=1)

p4.pipe.MyIngress.set_port_agent.add_with_set_sample_hd(ingress_port=143,agent_addr=0x0a0a0302,agent_id=2)


print(">>> simple_switch config done.")
