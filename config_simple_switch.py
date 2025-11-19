# config_simple_switch.py
# 這個檔案會在 bfshell 的 bfrt_python 環境裡執行，
# 變數 bfrt, simple_switch 都已經幫你準備好了。

# 如果你以前在 CLI 是先打：
#   bfrt.simple_switch.pipe ...
# 那你在檔案裡也可以這樣寫；只是你現在已經在 simple_switch namespace 下，
# 假設 CLI 裡現在 prompt 是：
#   simple_switch >
# 那就直接用 simple_switch 開頭就好了。

simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=140, port=141)

simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=141, port=140)

simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=142, port=143)

simple_switch.pipe.MyIngress.ingress_port_forward.add_with_set_out_port(
    ingress_port=143, port=142)

simple_switch.pipe.MyIngress.port_sampling_rate.add_with_set_sampling_rate(
    ingress_port=140, sampling_rate=100)

print(">>> simple_switch config done.")
