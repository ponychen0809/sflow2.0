/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48>   mac_addr_t;
typedef bit<32>   ipv4_addr_t;
typedef bit<16>   l4_port_t;
typedef bit<32>   timestamp_t;

enum bit<10> MIRROR_SESSION_t {
    TO_CPU = 26
}

enum bit<8> PKT_TYPE_t {
    NORMAL = 0,
    TO_CPU = 1
}

enum bit<3> MIRROR_TYPE_t {
    I2E = 1,
    E2E = 2
}

enum bit<16> ETHER_TYPE_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    TPID = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847,
    TO_CPU = 0xBF01,
    EVICT = 0xBF02
}

enum bit<8> PROTOCOL_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58
}

// Headers
// information sent to cpu

header bridge_h {
    PKT_TYPE_t      pkt_type;
    bit<32>         to_cpu_count;
}

header to_cpu_h {
    bit<8> flow_num;
}

header flow_h {
    ipv4_addr_t     src_ip_addr; /* 1-4 byte */
    ipv4_addr_t     dst_ip_addr; /* 5-8 byte */
    PROTOCOL_t      protocol; /* 9 byte */
    bit<32>         ports;    /* 10-13 byte */
    // l4_port_t       src_port; /* 10-11 byte */
    // l4_port_t       dst_port; /* 12-13 byte */
    timestamp_t     last_timestamp; /* 14-17 byte */
    bit<32>         byte_count; /* 18-21 byte */
    // bit<8>          padding; /* 22 byte */
}

header ethernet_h {
    mac_addr_t      dst_addr;
    mac_addr_t      src_addr;
    ETHER_TYPE_t    ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>          version;
    bit<4>          ihl;
    bit<8>          diffserv;
    bit<16>         total_len;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         frag_offset;
    bit<8>          ttl;
    PROTOCOL_t      protocol;
    bit<16>         hdr_checksum;
    ipv4_addr_t     src_addr;
    ipv4_addr_t     dst_addr;
}

header ipv4_options_t {
   varbit<320> options;
}

header tcp_h {
    l4_port_t       src_port;
    l4_port_t       dst_port;
    bit<32>         seq_no;
    bit<32>         ack_no;
    bit<4>          data_offset;
    bit<3>          res;
    bit<3>          ecn;
    bit<6>          ctrl;
    bit<16>         window;
    bit<16>         checksum;
    bit<16>         urgent_ptr;
}

header tcp_options_t {
   varbit<320> options;
}

header udp_h {
    l4_port_t       src_port;
    l4_port_t       dst_port;
    bit<16>         length;
    bit<16>         checksum;
}

header arp_h {
	bit<16>         hw_type;
	ETHER_TYPE_t    proto_type;
	bit<8>          hw_addr_len;
	bit<8>          proto_addr_len;
	bit<16>         opcode;
}

header arp_ipv4_h {
	mac_addr_t      src_hw_addr;
	ipv4_addr_t     src_proto_addr;
	mac_addr_t      dst_hw_addr;
	ipv4_addr_t     dst_proto_addr;
}

struct my_ingress_headers_t {
    bridge_h        bridge;
    ethernet_h      ethernet;
    to_cpu_h        to_cpu;
    flow_h          flow;
    flow_h          flow_5;
    flow_h          flow_4;
    flow_h          flow_3;
    flow_h          flow_2;
    vlan_tag_h      vlan_tag;
    ipv4_h          ipv4;
    // ipv4_options_t  ipv4_options;
    tcp_h           tcp;
    udp_h           udp;
	// arp_h                   arp;
	// arp_ipv4_h              arp_ipv4;
}

// Metadata
struct my_ingress_metadata_t {
    bit<1>          is_statistic;
    bit<1>          is_to_cpu;
    ipv4_addr_t     src_ip_addr;
    ipv4_addr_t     dst_ip_addr;
    PROTOCOL_t      protocol;
    bit<32>         ports;
    l4_port_t       src_port;
    l4_port_t       dst_port;
    MirrorId_t      mirror_session;
    bit<32>         byte_count;
}

struct my_egress_headers_t {
    ethernet_h      ethernet;
    to_cpu_h        to_cpu;
    flow_h          flow;
    flow_h          flow_8;
    flow_h          flow_7;
    flow_h          flow_6;
    flow_h          flow_5;
    vlan_tag_h      vlan_tag;
    ipv4_h          ipv4;
    // ipv4_options_t  ipv4_options;
    tcp_h           tcp;
    udp_h           udp;
}

// Metadata
struct my_egress_metadata_t {
    bridge_h        bridge;
    bit<32>         to_cpu_count;
    ipv4_addr_t     src_ip_addr;
    ipv4_addr_t     dst_ip_addr;
    PROTOCOL_t      protocol;
    bit<32>         ports;
    l4_port_t       src_port;
    l4_port_t       dst_port;
    timestamp_t     last_timestamp;
    bit<32>         byte_count;
    // bit<16>         checksum_state;
}

/*===============================
=            Parsing            =
===============================*/
/* Ingress Parser */

// Parser for tofino-specific metadata.
parser TofinoIngressParser(
        packet_in pkt,   
        out my_ingress_headers_t hdr,
        out my_ingress_metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(64); // skip this.
        transition accept;
    }
}

// my ingress parser
parser MyIngressParser(packet_in pkt,
                out my_ingress_headers_t hdr,
                out my_ingress_metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        TofinoIngressParser.apply(pkt, hdr, meta, ig_intr_md);
        meta.is_statistic = 0;
        meta.is_to_cpu = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHER_TYPE_t.TPID:  parse_vlan_tag;
            ETHER_TYPE_t.IPV4:  parse_ipv4;
            ETHER_TYPE_t.EVICT:  parse_evict;
            default: accept;
        }
    }

    state parse_evict {
        meta.is_to_cpu = 1;
        meta.src_ip_addr = 0;
        meta.dst_ip_addr = 0;
        meta.protocol = (PROTOCOL_t)0;
        meta.ports = 0;
        meta.byte_count = 0;
        transition accept;
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHER_TYPE_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        meta.src_ip_addr = hdr.ipv4.src_addr;
        meta.dst_ip_addr = hdr.ipv4.dst_addr;
        meta.protocol = hdr.ipv4.protocol;

        transition select(hdr.ipv4.protocol) {
            PROTOCOL_t.TCP:    parse_tcp;
            PROTOCOL_t.UDP:    parse_udp;
            default: accept;
        }
        // transition select(hdr.ipv4.ihl) {
        //     5: check_ip_protocol;
        //     default: parse_ipv4_options;
        // }
    }

    // state parse_ipv4_options {
    //     pkt.extract(hdr.ipv4_options, (bit<32>)(((bit<16>)hdr.ipv4.ihl - 5) * 32));
    //     transition check_ip_protocol;
    // }

    // state check_ip_protocol {
    //     transition select(hdr.ipv4.protocol) {
    //         PROTOCOL_t.TCP:    parse_tcp;
    //         PROTOCOL_t.UDP:    parse_udp;
    //         default: accept;
    //     }
    // }

    state parse_tcp {
        pkt.extract(hdr.tcp);

        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        meta.is_statistic = 1;

        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);

        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        meta.is_statistic = 1;

        transition accept;
    }

    // state parse_tcp {
    //     packet.extract(hdr.tcp);
    //     transition select(hdr.tcp.dataOffset) {
    //         5: check_app_type;
    //         default: parse_tcp_options;
    //     }
    // }
    // state parse_tcp_options {
    //     packet.extract(hdr.tcp_options, (bit<32>)(((bit<16>)hdr.tcp.dataOffset - 5) * 32));
    //     transition check_app_type;
    // }

	// state parse_arp {
	// 	pkt.extract(hdr.arp);
	// 	transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
	// 		(0x0001, ether_type_t.IPV4) : parse_arp_ipv4;
	// 		default: accept; // Currently the same as accept
	// 	}
	// }

	// state parse_arp_ipv4 {
	// 	pkt.extract(hdr.arp_ipv4);
	// 	meta.dst_ipv4 = hdr.arp_ipv4.dst_proto_addr;
	// 	transition accept;
	// }

}


/* Ingress Pipeline */

control MyIngress(
                  /* User */
                  inout my_ingress_headers_t hdr,
                  inout my_ingress_metadata_t meta,
                  /* Intrinsic */
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) flow_counter;

    DirectRegister<bit<32>>() timestamp_reg_dir;
    DirectRegisterAction<bit<32>, bit<32>>(timestamp_reg_dir) timestamp_reg_dir_action = {
        void apply(inout bit<32> register_val) {
            // register_val = (bit<32>)(ig_intr_md.ingress_mac_tstamp >> 16);
            register_val = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        }
    };
    
    Register<bit<32>, bit<1>>(1, 0) to_cpu_counter_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(to_cpu_counter_register_table) to_cpu_counter_register_table_action_read_count = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = register_val+1;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(to_cpu_counter_register_table) to_cpu_counter_register_table_action_read_reset = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = 0;
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_register_table) src_ip_addr_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_register_table) dst_ip_addr_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_register_table) protocol_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_register_table) ports_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_register_table) byte_count_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_register_table) last_timestamp_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_2_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_2_register_table) src_ip_addr_2_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_2_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_2_register_table) dst_ip_addr_2_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_2_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_2_register_table) protocol_2_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_2_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_2_register_table) ports_2_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_2_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_2_register_table) byte_count_2_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_2_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_2_register_table) last_timestamp_2_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_3_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_3_register_table) src_ip_addr_3_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_3_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_3_register_table) dst_ip_addr_3_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_3_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_3_register_table) protocol_3_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_3_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_3_register_table) ports_3_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_3_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_3_register_table) byte_count_3_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_3_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_3_register_table) last_timestamp_3_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_4_register_table) src_ip_addr_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_4_register_table) dst_ip_addr_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_4_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_4_register_table) protocol_4_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_4_register_table) ports_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_4_register_table) byte_count_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_4_register_table) last_timestamp_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        }
    };

    Register<bit<32>, bit<8>>(8, 0) debug_counter_register_table;
    RegisterAction<bit<32>, bit<8>, bit<32>>(debug_counter_register_table) debug_counter_register_table_action_read_count = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = register_val+1;
        }
    };

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action set_bridge() {
        hdr.bridge.setValid();
        hdr.bridge.pkt_type = PKT_TYPE_t.NORMAL;
    }

    action count() {
        flow_counter.count();
        timestamp_reg_dir_action.execute();
    }

    action mirror_to_cpu(){
        meta.is_to_cpu = 1;
    }

    action send_to_cpu() {
        ig_tm_md.ucast_egress_port = 192; // orignal packet send to cpu port
        hdr.bridge.pkt_type = PKT_TYPE_t.TO_CPU;
        hdr.vlan_tag.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        hdr.udp.setInvalid();

        hdr.to_cpu.setValid();
        hdr.ethernet.dst_addr = 0x000200000300;
        hdr.ethernet.ether_type = ETHER_TYPE_t.TO_CPU;
    }

    action set_mirror_to_cpu() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_t.I2E;
        meta.mirror_session = (bit<10>)ig_tm_md.ucast_egress_port; // mirror to orignal egress port; bit<10>mirror_session 可包含 bit<9> ucast_egress_port
        
        hdr.flow.setValid();
        hdr.flow.src_ip_addr = meta.src_ip_addr;
        hdr.flow.dst_ip_addr = meta.dst_ip_addr;
        hdr.flow.protocol = meta.protocol;
        hdr.flow.ports = meta.ports;
        // hdr.flow.src_port = meta.src_port;
        // hdr.flow.dst_port = meta.dst_port;
        // hdr.flow.last_timestamp = (bit<32>)(ig_intr_md.ingress_mac_tstamp >> 16);
        hdr.flow.last_timestamp = (bit<32>)(ig_prsr_md.global_tstamp >> 8);
        hdr.flow.byte_count = meta.byte_count;

        send_to_cpu();
    }

    action set_pop_entry(){
        meta.is_statistic = 0;
        mirror_to_cpu();
    }

    action ipv4_forward(mac_addr_t dst_mac_addr, PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_mac_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action simple_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        ig_tm_md.mcast_grp_a = mcast_grp;
    }

    action no_statistic() {
        meta.is_statistic = 0;
    }


    table mac_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }

        actions = {
            simple_forward;
            set_mcast_grp;
            @defaultonly NoAction;
        }
        size = 1024;
        const default_action = NoAction;
    }
    
    table black_list_table {
        key = {
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.dst_addr: ternary;
        }

        actions = {
            no_statistic;
            @defaultonly NoAction;
        }
        size = 6;
        const entries = {
            (_, 0x00a0c9000000): no_statistic();
            (0x00a0c9000000, _): no_statistic();
            (_, 0x341278560100): no_statistic();
            (0x341278560100, _): no_statistic();
            (_, 0x000200000300): no_statistic();
            (0x000200000300, _): no_statistic();
        }
        const default_action = NoAction;
    }

    table ipv4_table {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            ipv4_forward;
            @defaultonly NoAction;
        }
        size = 1024;
        const default_action = NoAction;
    }

    table flow_pop_table {
        key = {
            meta.src_ip_addr: exact;
            meta.dst_ip_addr : exact;
            meta.protocol : exact;
            meta.src_port : exact;
            meta.dst_port : exact;
        }
        actions = {
            @defaultonly NoAction;
            set_pop_entry;
        }
        size = 1024;
        const default_action = NoAction;
    }

    @idletime_precision(6)
    table flow_statistic_table {
        key = {
            meta.src_ip_addr: exact;
            meta.dst_ip_addr : exact;
            meta.protocol : exact;
            meta.src_port : exact;
            meta.dst_port : exact;
        }
        actions = {
            @defaultonly mirror_to_cpu;
            count;
        }
        size = 10240; // limit: 266240
        counters = flow_counter;
        idle_timeout = true;
        registers = timestamp_reg_dir;
        const default_action = mirror_to_cpu;
    }
    
    apply {
        set_bridge();
        if (!mac_table.apply().hit) {
            if (hdr.ipv4.isValid()) {
                ipv4_table.apply();
            }
        }
        
        
        black_list_table.apply();
        if (meta.is_statistic == 1) {
            // meta.byte_count 只需在這做一次
            meta.byte_count = (bit<32>)hdr.ipv4.total_len;
            meta.ports[15:0] = meta.dst_port;
            meta.ports[31:16] = meta.src_port;
            if (hdr.vlan_tag.isValid()) {
                meta.byte_count = meta.byte_count + 18;
            }
            else {
                meta.byte_count = meta.byte_count + 14;
            }

            flow_pop_table.apply();
        }
        if (meta.is_statistic == 1) {
            flow_statistic_table.apply();
        }

        if (meta.is_to_cpu == 1) {
            // if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
            //     hdr.bridge.to_cpu_count = to_cpu_counter_register_table_action_read_reset.execute(0);
            // }
            // else {
            //     hdr.bridge.to_cpu_count = to_cpu_counter_register_table_action_read_count.execute(0);
            // }
            hdr.bridge.to_cpu_count = to_cpu_counter_register_table_action_read_count.execute(0);

            if (hdr.bridge.to_cpu_count[1:0] == 3) {
                hdr.flow_2.src_ip_addr = src_ip_addr_register_table_action_read_set.execute(0);
                hdr.flow_2.dst_ip_addr = dst_ip_addr_register_table_action_read_set.execute(0);
                hdr.flow_2.protocol = (PROTOCOL_t)protocol_register_table_action_read_set.execute(0);
                hdr.flow_2.ports = ports_register_table_action_read_set.execute(0);
                hdr.flow_2.byte_count = byte_count_register_table_action_read_set.execute(0);
                hdr.flow_2.last_timestamp = last_timestamp_register_table_action_read_set.execute(0);

                hdr.flow_3.src_ip_addr = src_ip_addr_2_register_table_action_read_set.execute(0);
                hdr.flow_3.dst_ip_addr = dst_ip_addr_2_register_table_action_read_set.execute(0);
                hdr.flow_3.protocol = (PROTOCOL_t)protocol_2_register_table_action_read_set.execute(0);
                hdr.flow_3.ports = ports_2_register_table_action_read_set.execute(0);
                hdr.flow_3.byte_count = byte_count_2_register_table_action_read_set.execute(0);
                hdr.flow_3.last_timestamp = last_timestamp_2_register_table_action_read_set.execute(0);
                
                hdr.flow_4.src_ip_addr = src_ip_addr_3_register_table_action_read_set.execute(0);
                hdr.flow_4.dst_ip_addr = dst_ip_addr_3_register_table_action_read_set.execute(0);
                hdr.flow_4.protocol = (PROTOCOL_t)protocol_3_register_table_action_read_set.execute(0);
                hdr.flow_4.ports = ports_3_register_table_action_read_set.execute(0);
                hdr.flow_4.byte_count = byte_count_3_register_table_action_read_set.execute(0);
                hdr.flow_4.last_timestamp = last_timestamp_3_register_table_action_read_set.execute(0);

                // hdr.flow_5.src_ip_addr = src_ip_addr_4_register_table_action_read_set.execute(0);
                // hdr.flow_5.dst_ip_addr = dst_ip_addr_4_register_table_action_read_set.execute(0);
                // hdr.flow_5.protocol = (PROTOCOL_t)protocol_4_register_table_action_read_set.execute(0);
                // hdr.flow_5.ports = ports_4_register_table_action_read_set.execute(0);
                // hdr.flow_5.byte_count = byte_count_4_register_table_action_read_set.execute(0);
                // hdr.flow_5.last_timestamp = last_timestamp_4_register_table_action_read_set.execute(0);

                hdr.flow_2.setValid();
                hdr.flow_3.setValid();
                hdr.flow_4.setValid();
                // hdr.flow_5.setValid();
                if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
                    send_to_cpu();
                    hdr.to_cpu.flow_num = 3;
                }
                else {
                    set_mirror_to_cpu();
                    hdr.to_cpu.flow_num = 4;
                }
                debug_counter_register_table_action_read_count.execute(0);
            }
            // else if (hdr.bridge.to_cpu_count[1:0] == 3) {
            //     hdr.flow_5.src_ip_addr = src_ip_addr_4_register_table_action_read_set.execute(0);
            //     hdr.flow_5.dst_ip_addr = dst_ip_addr_4_register_table_action_read_set.execute(0);
            //     hdr.flow_5.protocol = (PROTOCOL_t)protocol_4_register_table_action_read_set.execute(0);
            //     hdr.flow_5.ports = ports_4_register_table_action_read_set.execute(0);
            //     hdr.flow_5.byte_count = byte_count_4_register_table_action_read_set.execute(0);
            //     hdr.flow_5.last_timestamp = last_timestamp_4_register_table_action_read_set.execute(0);
            //     if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
            //         drop();
            //     }
            // }
            else if (hdr.bridge.to_cpu_count[1:0] == 2) {
                hdr.flow_4.src_ip_addr = src_ip_addr_3_register_table_action_read_set.execute(0);
                hdr.flow_4.dst_ip_addr = dst_ip_addr_3_register_table_action_read_set.execute(0);
                hdr.flow_4.protocol = (PROTOCOL_t)protocol_3_register_table_action_read_set.execute(0);
                hdr.flow_4.ports = ports_3_register_table_action_read_set.execute(0);
                hdr.flow_4.byte_count = byte_count_3_register_table_action_read_set.execute(0);
                hdr.flow_4.last_timestamp = last_timestamp_3_register_table_action_read_set.execute(0);
                if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
                    drop();
                }
            }
            else if (hdr.bridge.to_cpu_count[1:0] == 1) {
                hdr.flow_3.src_ip_addr = src_ip_addr_2_register_table_action_read_set.execute(0);
                hdr.flow_3.dst_ip_addr = dst_ip_addr_2_register_table_action_read_set.execute(0);
                hdr.flow_3.protocol = (PROTOCOL_t)protocol_2_register_table_action_read_set.execute(0);
                hdr.flow_3.ports = ports_2_register_table_action_read_set.execute(0);
                hdr.flow_3.byte_count = byte_count_2_register_table_action_read_set.execute(0);
                hdr.flow_3.last_timestamp = last_timestamp_2_register_table_action_read_set.execute(0);
                if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
                    drop();
                }
            }
            else if (hdr.bridge.to_cpu_count[1:0] == 0) {
                hdr.flow_2.src_ip_addr = src_ip_addr_register_table_action_read_set.execute(0);
                hdr.flow_2.dst_ip_addr = dst_ip_addr_register_table_action_read_set.execute(0);
                hdr.flow_2.protocol = (PROTOCOL_t)protocol_register_table_action_read_set.execute(0);
                hdr.flow_2.ports = ports_register_table_action_read_set.execute(0);
                hdr.flow_2.byte_count = byte_count_register_table_action_read_set.execute(0);
                hdr.flow_2.last_timestamp = last_timestamp_register_table_action_read_set.execute(0);
                if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
                    drop();
                }
            }
            // else {
            //     if (hdr.ethernet.ether_type == ETHER_TYPE_t.EVICT) {
            //         send_to_cpu();
            //         hdr.to_cpu.flow_num = 0;
            //         ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            //     }
            //     else {
            //         set_mirror_to_cpu();
            //         hdr.to_cpu.flow_num = 1;
            //         ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            //     }
            // }
        }

    }
}

/* Ingress Deparser*/

control MyIngressDeparser(packet_out pkt,
                            /* User */
                            inout my_ingress_headers_t hdr,
                            in my_ingress_metadata_t meta,
                            /* Intrinsic */
                            in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
                                
    // Checksum() ipv4_checksum;
    Mirror() mirror;
    
    apply {
        // if(hdr.ipv4.isValid()){
        //     hdr.ipv4.hdr_checksum = ipv4_checksum.update({
        //         /* 16-bit word  0   */ hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
        //         /* 16-bit word  1   */ hdr.ipv4.total_len,
        //         /* 16-bit word  2   */ hdr.ipv4.identification,
        //         /* 16-bit word  3   */ hdr.ipv4.flags, hdr.ipv4.frag_offset,
        //         /* 16-bit word  4   */ hdr.ipv4.ttl, hdr.ipv4.protocol,
        //         /* 16-bit word  5 skip hdr.ipv4.hdrChecksum, */
        //         /* 16-bit word  6-7 */ hdr.ipv4.src_addr,
        //         /* 16-bit word  8-9 */ hdr.ipv4.dst_addr
        //     });
        // }
        pkt.emit(hdr);
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_t.I2E) {
            mirror.emit<bridge_h>(meta.mirror_session, {PKT_TYPE_t.NORMAL, 0});
        }
    }
}

/* Egress pipeline */

parser MyEgressParser(
        packet_in pkt,
        out my_egress_headers_t hdr,
        out my_egress_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    // Checksum() l4_checksum;

    state start {
        pkt.extract(eg_intr_md);
        transition parse_bridge;
    }
    
    state parse_bridge {
        pkt.extract(meta.bridge);
        transition select(meta.bridge.pkt_type) {
            PKT_TYPE_t.NORMAL : parse_ethernet;
            // PKT_TYPE_t.TO_CPU : parse_ethernet;
            default : accept;
        }
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHER_TYPE_t.TPID:  parse_vlan_tag;
            ETHER_TYPE_t.IPV4:  parse_ipv4;
            ETHER_TYPE_t.TO_CPU:  parse_to_cpu;
            default: accept;
        }
    }
    
    state parse_to_cpu {
        pkt.extract(hdr.to_cpu);
        meta.src_ip_addr = 0;
        meta.dst_ip_addr = 0;
        meta.protocol = (PROTOCOL_t)0;
        meta.ports = 0;
        meta.last_timestamp = 0;
        meta.byte_count = 0;
        transition select(hdr.to_cpu.flow_num) {
            0 : accept;
            7 : accept;
            default : parse_flow;
        }
    }
    
    state parse_flow {
        pkt.extract(hdr.flow);
        meta.src_ip_addr = hdr.flow.src_ip_addr;
        meta.dst_ip_addr = hdr.flow.dst_ip_addr;
        meta.protocol = hdr.flow.protocol;
        meta.ports = hdr.flow.ports;
        meta.last_timestamp = hdr.flow.last_timestamp;
        meta.byte_count = hdr.flow.byte_count;
        transition accept;
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHER_TYPE_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        // l4_checksum.subtract({
        //     /* 16-bit words 0-1 */ hdr.ipv4.src_addr,
        //     /* 16-bit words 2-3 */ hdr.ipv4.dst_addr
        // });

        transition select(hdr.ipv4.protocol) {
            PROTOCOL_t.TCP:    parse_tcp;
            PROTOCOL_t.UDP:    parse_udp;
            default: accept;
        }
        // transition select(hdr.ipv4.ihl) {
        //     5: check_ip_protocol;
        //     default: parse_ipv4_options;
        // }
    }

    // state parse_ipv4_options {
    //     pkt.extract(hdr.ipv4_options, (bit<32>)(((bit<16>)hdr.ipv4.ihl - 5) * 32));
    //     transition check_ip_protocol;
    // }

    // state check_ip_protocol {
    //     transition select(hdr.ipv4.protocol) {
    //         PROTOCOL_t.TCP:    parse_tcp;
    //         PROTOCOL_t.UDP:    parse_udp;
    //         default: accept;
    //     }
    // }

    state parse_tcp {
        pkt.extract(hdr.tcp);

        // l4_checksum.subtract({
        //     /* TCP 16-bit word 0    */ hdr.tcp.src_port,
        //     /* TCP 16-bit word 1    */ hdr.tcp.dst_port,
        //     /* TCP 16-bit words 2-3 */ hdr.tcp.seq_no,
        //     /* TCP 16-bit words 4-5 */ hdr.tcp.ack_no,
        //     /* TCP 16-bit word 6    */ hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl,
        //     /* TCP 16-bit word 7    */ hdr.tcp.window,
        //     /* TCP 16-bit word 8    */ hdr.tcp.checksum,
        //     /* TCP 16-bit word 9    */ hdr.tcp.urgent_ptr
        // });
        // meta.checksum_state = l4_checksum.get();

        // transition select(hdr.tcp.data_offset) {
        //     5: parse_flow;
        //     default: parse_tcp_options;
        // }
        transition accept;
    }

    // state parse_tcp_options {
    //     packet.extract(hdr.tcp_options, (bit<32>)(((bit<16>)hdr.tcp.data_offset - 5) * 32));
    //     transition parse_flow;
    // }

    state parse_udp {
        pkt.extract(hdr.udp);

        // l4_checksum.subtract({
        //     /* UDP 16-bit word 0 */ hdr.udp.src_port,
        //     /* UDP 16-bit word 1 */ hdr.udp.dst_port,
        //     /* UDP 16-bit word 2 */ hdr.udp.length,
        //     /* UDP 16-bit word 3 */ hdr.udp.checksum
        // });
        // meta.checksum_state = l4_checksum.get();

        transition accept;
    }

}

control MyEgress(
        inout my_egress_headers_t hdr,
        inout my_egress_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_4_register_table) src_ip_addr_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_4_register_table) dst_ip_addr_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_4_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_4_register_table) protocol_4_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_4_register_table) ports_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_4_register_table) byte_count_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_4_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_4_register_table) last_timestamp_4_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.last_timestamp;
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_5_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_5_register_table) src_ip_addr_5_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_5_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_5_register_table) dst_ip_addr_5_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_5_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_5_register_table) protocol_5_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_5_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_5_register_table) ports_5_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_5_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_5_register_table) byte_count_5_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_5_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_5_register_table) last_timestamp_5_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.last_timestamp;
        }
    };

    
    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_6_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_6_register_table) src_ip_addr_6_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_6_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_6_register_table) dst_ip_addr_6_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_6_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_6_register_table) protocol_6_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_6_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_6_register_table) ports_6_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_6_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_6_register_table) byte_count_6_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_6_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_6_register_table) last_timestamp_6_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.last_timestamp;
        }
    };

    Register<bit<32>, bit<1>>(1, 0) src_ip_addr_7_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(src_ip_addr_7_register_table) src_ip_addr_7_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.src_ip_addr;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) dst_ip_addr_7_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(dst_ip_addr_7_register_table) dst_ip_addr_7_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.dst_ip_addr;
        }
    };
    Register<bit<8>, bit<1>>(1, 0) protocol_7_register_table;
    RegisterAction<bit<8>, bit<1>, bit<8>>(protocol_7_register_table) protocol_7_register_table_action_read_set = {
        void apply(inout bit<8> register_val, out bit<8> read_val) {
            read_val = register_val;
            register_val = meta.protocol;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) ports_7_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ports_7_register_table) ports_7_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.ports;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) byte_count_7_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(byte_count_7_register_table) byte_count_7_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.byte_count;
        }
    };
    Register<bit<32>, bit<1>>(1, 0) last_timestamp_7_register_table;
    RegisterAction<bit<32>, bit<1>, bit<32>>(last_timestamp_7_register_table) last_timestamp_7_register_table_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = meta.last_timestamp;
        }
    };

    Register<bit<32>, bit<8>>(8, 0) debug_counter_register_table;
    RegisterAction<bit<32>, bit<8>, bit<32>>(debug_counter_register_table) debug_counter_register_table_action_read_count = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = register_val+1;
        }
    };

    action drop() {
        eg_intr_dprs_md.drop_ctl = 0x1;
    }

    apply {
        // if (meta.bridge.pkt_type == PKT_TYPE_t.TO_CPU) {
        //     if (eg_intr_md.egress_port == 176) {
        //         debug_counter_register_table_action_read_count.execute(1);
        //     }
        //     else if (eg_intr_md.egress_port == 177) {
        //         debug_counter_register_table_action_read_count.execute(2);
        //     }
        //     if (meta.bridge.to_cpu_count[2:0] == 7) {
        //         hdr.flow_5.src_ip_addr = src_ip_addr_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.dst_ip_addr = dst_ip_addr_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.protocol = (PROTOCOL_t)protocol_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.ports = ports_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.byte_count = byte_count_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.last_timestamp = last_timestamp_4_register_table_action_read_set.execute(0);

        //         hdr.flow_6.src_ip_addr = src_ip_addr_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.dst_ip_addr = dst_ip_addr_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.protocol = (PROTOCOL_t)protocol_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.ports = ports_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.byte_count = byte_count_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.last_timestamp = last_timestamp_5_register_table_action_read_set.execute(0);
                
        //         hdr.flow_7.src_ip_addr = src_ip_addr_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.dst_ip_addr = dst_ip_addr_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.protocol = (PROTOCOL_t)protocol_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.ports = ports_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.byte_count = byte_count_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.last_timestamp = last_timestamp_6_register_table_action_read_set.execute(0);
                
        //         hdr.flow_8.src_ip_addr = src_ip_addr_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.dst_ip_addr = dst_ip_addr_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.protocol = (PROTOCOL_t)protocol_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.ports = ports_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.byte_count = byte_count_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.last_timestamp = last_timestamp_7_register_table_action_read_set.execute(0);

        //         hdr.flow_5.setValid();
        //         hdr.flow_6.setValid();
        //         hdr.flow_7.setValid();
        //         hdr.flow_8.setValid();
        //     }
        //     else if (meta.bridge.to_cpu_count[2:0] == 6) {
        //         hdr.flow_8.src_ip_addr = src_ip_addr_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.dst_ip_addr = dst_ip_addr_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.protocol = (PROTOCOL_t)protocol_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.ports = ports_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.byte_count = byte_count_7_register_table_action_read_set.execute(0);
        //         hdr.flow_8.last_timestamp = last_timestamp_7_register_table_action_read_set.execute(0);
        //         drop();
        //     }
        //     else if (meta.bridge.to_cpu_count[2:0] == 5) {
        //         hdr.flow_7.src_ip_addr = src_ip_addr_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.dst_ip_addr = dst_ip_addr_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.protocol = (PROTOCOL_t)protocol_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.ports = ports_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.byte_count = byte_count_6_register_table_action_read_set.execute(0);
        //         hdr.flow_7.last_timestamp = last_timestamp_6_register_table_action_read_set.execute(0);
        //         drop();
        //     }
        //     else if (meta.bridge.to_cpu_count[2:0] == 4) {
        //         hdr.flow_6.src_ip_addr = src_ip_addr_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.dst_ip_addr = dst_ip_addr_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.protocol = (PROTOCOL_t)protocol_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.ports = ports_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.byte_count = byte_count_5_register_table_action_read_set.execute(0);
        //         hdr.flow_6.last_timestamp = last_timestamp_5_register_table_action_read_set.execute(0);
        //         drop();
        //     }
        //     else if (meta.bridge.to_cpu_count[2:0] == 3) {
        //         hdr.flow_5.src_ip_addr = src_ip_addr_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.dst_ip_addr = dst_ip_addr_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.protocol = (PROTOCOL_t)protocol_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.ports = ports_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.byte_count = byte_count_4_register_table_action_read_set.execute(0);
        //         hdr.flow_5.last_timestamp = last_timestamp_4_register_table_action_read_set.execute(0);
        //         drop();
        //     }
        //     else {
        //         drop();
        //     }
        // }
    }
}

control MyEgressDeparser(
        packet_out pkt,
        inout my_egress_headers_t hdr,
        in my_egress_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {
     
    Checksum() ipv4_checksum;
    // Checksum() l4_checksum;
    
    apply {
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                /* 16-bit word  0   */ hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                /* 16-bit word  1   */ hdr.ipv4.total_len,
                /* 16-bit word  2   */ hdr.ipv4.identification,
                /* 16-bit word  3   */ hdr.ipv4.flags, hdr.ipv4.frag_offset,
                /* 16-bit word  4   */ hdr.ipv4.ttl, hdr.ipv4.protocol,
                /* 16-bit word  5 skip hdr.ipv4.hdrChecksum, */
                /* 16-bit word  6-7 */ hdr.ipv4.src_addr,
                /* 16-bit word  8-9 */ hdr.ipv4.dst_addr
            });
            // l4_checksum.update({
            //     /* 16-bit words 0-1 */ hdr.ipv4.src_addr,
            //     /* 16-bit words 2-3 */ hdr.ipv4.dst_addr
            // });
        }

        // if (hdr.flow.isValid()) {
        //     l4_checksum.update({
        //         hdr.flow.src_addr,
        //         hdr.flow.dst_addr,
        //         hdr.flow.protocol,
        //         hdr.flow.src_port,
        //         hdr.flow.dst_port,
        //         hdr.flow.ingress_mac_tstamp,
        //         hdr.flow.padding
        //     });
        // }

        // if (hdr.tcp.isValid()) {
        //     hdr.tcp.checksum = l4_checksum.update({
        //         /* TCP 16-bit word 0    */ hdr.tcp.src_port,
        //         /* TCP 16-bit word 1    */ hdr.tcp.dst_port,
        //         /* TCP 16-bit words 2-3 */ hdr.tcp.seq_no,
        //         /* TCP 16-bit words 4-5 */ hdr.tcp.ack_no,
        //         /* TCP 16-bit word 6    */ hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl,
        //         /* TCP 16-bit word 7    */ hdr.tcp.window,
        //         /* TCP 16-bit word 8 skip hdr.tcp.checksum, */
        //         /* TCP 16-bit word 9    */ hdr.tcp.urgent_ptr,
        //         meta.checksum_state
        //     });
        // }

        // if (hdr.udp.isValid()) {
            // hdr.udp.checksum = l4_checksum.update({
            //     /* UDP 16-bit word 0 */ hdr.udp.src_port,
            //     /* UDP 16-bit word 1 */ hdr.udp.dst_port,
            //     /* UDP 16-bit word 2 */ hdr.udp.length
            //     /* UDP 16-bit word 3 skip hdr.udp.checksum */,
            //     meta.checksum_state
            // });


            // See Note 3 - If hdr.udp.checksum was received as 0, we
            // should never change it.  If the calculated checksum is
            // 0, send all 1 bits instead.
            // if (hdr.udp.checksum != 0) {
            //     hdr.udp.checksum = l4_checksum.get();
            //     if (hdr.udp.checksum == 0) {
            //         hdr.udp.checksum = 0xffff;
            //     }
            // }
        // }

        pkt.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(
    MyIngressParser(), MyIngress(), MyIngressDeparser(),
    MyEgressParser(), MyEgress(), MyEgressDeparser()
) pipe;

Switch(pipe) main;
