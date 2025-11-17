
build:
	~/p4_build.sh simple_switch.p4
clear:
	rm -f *log*
	rm -f ptf.pcap
	rm -rf __pycache__

run:
	~/p4_build.sh simple_switch.p4
bfrt:
	${SDE}/run_switchd.sh -p simple_switch