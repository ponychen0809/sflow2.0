## 設定從哪個port進來，從哪個port出去
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=140,port=141)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=141,port=140)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=142,port=143)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=143,port=142)

## 設定廣播
pre.node.add(DEV_PORT=[32], MULTICAST_LAG_ID=[], MULTICAST_NODE_ID=1, MULTICAST_RID=1)
pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[1], MULTICAST_NODE_L1_XID=[0], MULTICAST_NODE_L1_XID_VALID=[0])

## 開啟port
port-add 13/- 10G NONE
port-add 25/- 10G NONE
port-add 26/- 10G NONE

port-enb 13/-
port-enb 25/-
port-enb 26/-


simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=140,port=141)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=141,port=140)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=142,port=143)
simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(ingress_port=143,port=142)
pre.node.add(DEV_PORT=[32], MULTICAST_LAG_ID=[], MULTICAST_NODE_ID=1, MULTICAST_RID=1)
pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[1], MULTICAST_NODE_L1_XID=[0], MULTICAST_NODE_L1_XID_VALID=[0])



