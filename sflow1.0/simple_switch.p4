/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

#include "common/headers.p4"
#include "common/util.p4"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


/* Ingress Parser */
enum bit<3> MIRROR_TYPE_t {
    I2E = 1,
    E2E = 2
};
const bit<32> SAMPLING_RATE = 128;
parser MyIngressParser(packet_in pkt,
                out my_header_t hdr,
                out my_metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.pkt_len = (bit<32>)hdr.ipv4.total_len;
        meta.protocol   = (bit<32>)hdr.ipv4.protocol;
        meta.src_ip  = (bit<32>)hdr.ipv4.src_addr;
        meta.dst_ip  = (bit<32>)hdr.ipv4.dst_addr;
        meta.tos     = (bit<32>)hdr.ipv4.diffserv;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = (bit<32>)hdr.tcp.src_port;
        meta.dst_port = (bit<32>)hdr.tcp.dst_port;
        meta.tcp_flag = 0;

        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = (bit<32>)hdr.udp.src_port;
        meta.dst_port = (bit<32>)hdr.udp.dst_port;
        meta.tcp_flag = 0;
        transition accept;
    }
}

Register<bit<32>, bit<1>>(1,0) send_flag;
/* Ingress Pipeline */
control MyIngress(
                  /* User */
                  inout my_header_t hdr,
                  inout my_metadata_t meta,
                  /* Intrinsic */
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

//register             
    Register<bit<32>, bit<1>>(1,0) total_packets_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(total_packets_reg)
        set_total_packet = {
            void apply(inout bit<32> v, out bit<32> new_val) {
                if (v == 999){
                    v = 0;
                }else{
                    v       = v + 1;
                }
                new_val = v; 
            }
    };
    

    Register<bit<32>, bit<1>>(1,0) total_sample_count;
    RegisterAction<bit<32>, bit<1>, bit<32>>(total_sample_count)
        set_total_sample = {
            void apply(inout bit<32> v, out bit<32> new_val) {
                if (v == 3) {
                    v = 0;
                } else {
                    v = v + 1;
                }
                new_val = v;          // 把 +1 後的值回傳
            }
    };
//********************* register_0 *********************//
    Register<bit<32>,bit<1>>(1, 0) reg_ingress_port_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ingress_port_0) reg_ingress_port_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)ig_intr_md.ingress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_egress_port_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_egress_port_0) reg_egress_port_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>) ig_tm_md.ucast_egress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_pkt_length_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pkt_length_0) reg_pkt_length_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.total_len;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_protocol_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_protocol_0) reg_protocol_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.protocol;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_ip_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_ip_0) reg_src_ip_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_ip_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_ip_0) reg_dst_ip_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.dst_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_port_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_port_0) reg_src_port_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.src_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_port_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_port_0) reg_dst_port_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.dst_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tcp_flag_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tcp_flag_0) reg_tcp_flag_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)0;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tos_0;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tos_0) reg_tos_0_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.diffserv;
        }
    }; 

//********************* register_1 *********************//
    Register<bit<32>,bit<1>>(1, 0) reg_ingress_port_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ingress_port_1) reg_ingress_port_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)ig_intr_md.ingress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_egress_port_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_egress_port_1) reg_egress_port_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>) ig_tm_md.ucast_egress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_pkt_length_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pkt_length_1) reg_pkt_length_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.total_len;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_protocol_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_protocol_1) reg_protocol_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.protocol;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_ip_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_ip_1) reg_src_ip_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_ip_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_ip_1) reg_dst_ip_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.dst_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_port_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_port_1) reg_src_port_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.src_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_port_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_port_1) reg_dst_port_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.dst_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tcp_flag_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tcp_flag_1) reg_tcp_flag_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)0;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tos_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tos_1) reg_tos_1_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.diffserv;
        }
    };     

//********************* register_2 *********************//
    Register<bit<32>,bit<1>>(1, 0) reg_ingress_port_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ingress_port_2) reg_ingress_port_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)ig_intr_md.ingress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_egress_port_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_egress_port_2) reg_egress_port_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>) ig_tm_md.ucast_egress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_pkt_length_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pkt_length_2) reg_pkt_length_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.total_len;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_protocol_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_protocol_2) reg_protocol_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.protocol;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_ip_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_ip_2) reg_src_ip_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_ip_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_ip_2) reg_dst_ip_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.dst_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_port_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_port_2) reg_src_port_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.src_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_port_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_port_2) reg_dst_port_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.dst_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tcp_flag_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tcp_flag_2) reg_tcp_flag_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)0;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tos_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tos_2) reg_tos_2_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.diffserv;
        }
    }; 
//********************* register_3 *********************//
    Register<bit<32>,bit<1>>(1, 0) reg_ingress_port_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ingress_port_3) reg_ingress_port_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)ig_intr_md.ingress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_egress_port_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_egress_port_3) reg_egress_port_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>) ig_tm_md.ucast_egress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_pkt_length_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pkt_length_3) reg_pkt_length_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.total_len;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_protocol_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_protocol_3) reg_protocol_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.protocol;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_ip_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_ip_3) reg_src_ip_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_ip_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_ip_3) reg_dst_ip_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.dst_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_port_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_port_3) reg_src_port_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.src_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_port_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_port_3) reg_dst_port_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.dst_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tcp_flag_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tcp_flag_3) reg_tcp_flag_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)0;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tos_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tos_3) reg_tos_3_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.diffserv;
        }
    }; 

//********************* register_4 *********************//
    Register<bit<32>,bit<1>>(1, 0) reg_ingress_port_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ingress_port_4) reg_ingress_port_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)ig_intr_md.ingress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_egress_port_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_egress_port_4) reg_egress_port_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>) ig_tm_md.ucast_egress_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_pkt_length_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pkt_length_4) reg_pkt_length_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.total_len;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_protocol_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_protocol_4) reg_protocol_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.protocol;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_ip_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_ip_4) reg_src_ip_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_ip_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_ip_4) reg_dst_ip_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.dst_addr;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_src_port_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_src_port_4) reg_src_port_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.src_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_dst_port_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dst_port_4) reg_dst_port_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.udp.dst_port;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tcp_flag_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tcp_flag_4) reg_tcp_flag_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)0;
        }
    };

    Register<bit<32>,bit<1>>(1, 0) reg_tos_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tos_4) reg_tos_4_action_read_set = {
        void apply(inout bit<32> register_val, out bit<32> read_val) {
            read_val = register_val;
            register_val = (bit<32>)hdr.ipv4.diffserv;
        }
    }; 
//******************************************************//

    action send_multicast(bit<16> grp_id, bit<16> rid) {
        ig_tm_md.mcast_grp_a = grp_id;
        ig_tm_md.rid = rid;
    }


    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    table ipv4_table{
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    
    apply {
        ipv4_table.apply();

        bit<32> total_packet;
        bit<9> do_sample;
        if(ig_intr_md.ingress_port == 144){
            do_sample =1;
            total_packet = set_total_packet.execute(0);
        }else if(ig_intr_md.ingress_port == 145){
            do_sample =0;
        }else if(ig_intr_md.ingress_port == 149){
            do_sample =0;
        }else if(ig_intr_md.ingress_port == 147){
            do_sample = 0;
        }else{
            do_sample = 0;
        }

        if(do_sample == 1 && total_packet % 1024 == 0){
                bit<32> total_sample = set_total_sample.execute(0);
                if(total_sample == 1){
                    hdr.sflow_sample_0.input_if = reg_ingress_port_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.output_if = reg_egress_port_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.pkt_length = reg_pkt_length_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.protocol = reg_protocol_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.src_ip = reg_src_ip_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.dst_ip = reg_dst_ip_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.src_port = reg_src_port_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.dst_port = reg_dst_port_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.tcp_flags = reg_tcp_flag_0_action_read_set.execute(0);
                    hdr.sflow_sample_0.tos = reg_tos_0_action_read_set.execute(0);
                }else if (total_sample == 2){
                    hdr.sflow_sample_1.input_if = reg_ingress_port_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.output_if = reg_egress_port_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.pkt_length = reg_pkt_length_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.protocol = reg_protocol_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.src_ip = reg_src_ip_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.dst_ip = reg_dst_ip_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.src_port = reg_src_port_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.dst_port = reg_dst_port_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.tcp_flags = reg_tcp_flag_1_action_read_set.execute(0);
                    hdr.sflow_sample_1.tos = reg_tos_1_action_read_set.execute(0);
                }else if (total_sample == 3){
                    hdr.sflow_sample_2.input_if = reg_ingress_port_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.output_if = reg_egress_port_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.pkt_length = reg_pkt_length_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.protocol = reg_protocol_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.src_ip = reg_src_ip_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.dst_ip = reg_dst_ip_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.src_port = reg_src_port_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.dst_port = reg_dst_port_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.tcp_flags = reg_tcp_flag_2_action_read_set.execute(0);
                    hdr.sflow_sample_2.tos = reg_tos_2_action_read_set.execute(0);
                }
                else {
                    hdr.sflow_sample_3.input_if = reg_ingress_port_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.output_if = reg_egress_port_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.pkt_length = reg_pkt_length_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.protocol = reg_protocol_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.src_ip = reg_src_ip_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.dst_ip = reg_dst_ip_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.src_port = reg_src_port_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.dst_port = reg_dst_port_3_action_read_set.execute(0);
                    hdr.sflow_sample_3.tcp_flags = reg_tcp_flag_3_action_read_set.execute(0);
                    send_multicast(1, 1);      
                }

            
        }else if(ig_intr_md.ingress_port == 132){
            ig_tm_md.ucast_egress_port = 147;
            hdr.udp.dst_port = (bit<16>)6343;
            hdr.udp.hdr_length = (bit<16>)356;
            hdr.ipv4.dst_addr = 0x0a0a0302;
            hdr.sflow_hd.setValid();
            hdr.sflow_hd.version = (bit<32>)5;
            hdr.sflow_hd.address_type = (bit<32>)1;
            hdr.sflow_hd.agent_addr = (bit<32>)5;
            hdr.sflow_hd.sub_agent_id = (bit<32>)5;
            hdr.sflow_hd.sequence_number = (bit<32>)5;
            hdr.sflow_hd.uptime = (bit<32>)12345;
            hdr.sflow_hd.samples = (bit<32>)4;

            hdr.sflow_sample_0.setValid();
            hdr.sflow_sample_0.sample_type = (bit<32>)1;
            hdr.sflow_sample_0.sample_length = (bit<32>)80;
            hdr.sflow_sample_0.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample_0.source_id = (bit<32>)1;
            hdr.sflow_sample_0.sampling_rate = (bit<32>)256;
            hdr.sflow_sample_0.sample_pool = (bit<32>)1;
            hdr.sflow_sample_0.drops = (bit<32>)0;
            hdr.sflow_sample_0.record_count = (bit<32>)1;
            hdr.sflow_sample_0.enterprise_format = (bit<32>)1;
            hdr.sflow_sample_0.flow_length = (bit<32>)32;
            hdr.sflow_sample_0.input_if = reg_ingress_port_0_action_read_set.execute(0);
            hdr.sflow_sample_0.output_if = reg_egress_port_0_action_read_set.execute(0);
            hdr.sflow_sample_0.pkt_length = reg_pkt_length_0_action_read_set.execute(0);
            hdr.sflow_sample_0.protocol = reg_protocol_0_action_read_set.execute(0);
            hdr.sflow_sample_0.src_ip = reg_src_ip_0_action_read_set.execute(0);
            hdr.sflow_sample_0.dst_ip = reg_dst_ip_0_action_read_set.execute(0);
            hdr.sflow_sample_0.src_port = reg_src_port_0_action_read_set.execute(0);
            hdr.sflow_sample_0.dst_port = reg_dst_port_0_action_read_set.execute(0);
            hdr.sflow_sample_0.tcp_flags = reg_tcp_flag_0_action_read_set.execute(0);
            hdr.sflow_sample_0.tos = reg_tos_0_action_read_set.execute(0);

            hdr.sflow_sample_1.setValid();
            hdr.sflow_sample_1.sample_type = (bit<32>)1;
            hdr.sflow_sample_1.sample_length = (bit<32>)80;
            hdr.sflow_sample_1.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample_1.source_id = (bit<32>)1;
            hdr.sflow_sample_1.sampling_rate = (bit<32>)256;
            hdr.sflow_sample_1.sample_pool = (bit<32>)1;
            hdr.sflow_sample_1.drops = (bit<32>)0;
            hdr.sflow_sample_1.record_count = (bit<32>)1;
            hdr.sflow_sample_1.enterprise_format = (bit<32>)1;
            hdr.sflow_sample_1.flow_length = (bit<32>)32;
            hdr.sflow_sample_1.input_if = reg_ingress_port_1_action_read_set.execute(0);
            hdr.sflow_sample_1.output_if = reg_egress_port_1_action_read_set.execute(0);
            hdr.sflow_sample_1.pkt_length = reg_pkt_length_1_action_read_set.execute(0);
            hdr.sflow_sample_1.protocol = reg_protocol_1_action_read_set.execute(0);
            hdr.sflow_sample_1.src_ip = reg_src_ip_1_action_read_set.execute(0);
            hdr.sflow_sample_1.dst_ip = reg_dst_ip_1_action_read_set.execute(0);
            hdr.sflow_sample_1.src_port = reg_src_port_1_action_read_set.execute(0);
            hdr.sflow_sample_1.dst_port = reg_dst_port_1_action_read_set.execute(0);
            hdr.sflow_sample_1.tcp_flags = reg_tcp_flag_1_action_read_set.execute(0);
            hdr.sflow_sample_1.tos = reg_tos_1_action_read_set.execute(0);

            hdr.sflow_sample_2.setValid();
            hdr.sflow_sample_2.sample_type = (bit<32>)1;
            hdr.sflow_sample_2.sample_length = (bit<32>)80;
            hdr.sflow_sample_2.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample_2.source_id = (bit<32>)1;
            hdr.sflow_sample_2.sampling_rate = (bit<32>)256;
            hdr.sflow_sample_2.sample_pool = (bit<32>)1;
            hdr.sflow_sample_2.drops = (bit<32>)0;
            hdr.sflow_sample_2.record_count = (bit<32>)1;
            hdr.sflow_sample_2.enterprise_format = (bit<32>)1;
            hdr.sflow_sample_2.flow_length = (bit<32>)32;
            hdr.sflow_sample_2.input_if = reg_ingress_port_2_action_read_set.execute(0);
            hdr.sflow_sample_2.output_if = reg_egress_port_2_action_read_set.execute(0);
            hdr.sflow_sample_2.pkt_length = reg_pkt_length_2_action_read_set.execute(0);
            hdr.sflow_sample_2.protocol = reg_protocol_2_action_read_set.execute(0);
            hdr.sflow_sample_2.src_ip = reg_src_ip_2_action_read_set.execute(0);
            hdr.sflow_sample_2.dst_ip = reg_dst_ip_2_action_read_set.execute(0);
            hdr.sflow_sample_2.src_port = reg_src_port_2_action_read_set.execute(0);
            hdr.sflow_sample_2.dst_port = reg_dst_port_2_action_read_set.execute(0);
            hdr.sflow_sample_2.tcp_flags = reg_tcp_flag_2_action_read_set.execute(0);
            hdr.sflow_sample_2.tos = reg_tos_2_action_read_set.execute(0);
            
            hdr.sflow_sample_3.setValid();
            hdr.sflow_sample_3.sample_type = (bit<32>)1;
            hdr.sflow_sample_3.sample_length = (bit<32>)80;
            hdr.sflow_sample_3.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample_3.source_id = (bit<32>)1;
            hdr.sflow_sample_3.sampling_rate = (bit<32>)256;
            hdr.sflow_sample_3.sample_pool = (bit<32>)1;
            hdr.sflow_sample_3.drops = (bit<32>)0;
            hdr.sflow_sample_3.record_count = (bit<32>)1;
            hdr.sflow_sample_3.enterprise_format = (bit<32>)1;
            hdr.sflow_sample_3.flow_length = (bit<32>)32;
            hdr.sflow_sample_3.input_if = reg_ingress_port_3_action_read_set.execute(0);
            hdr.sflow_sample_3.output_if = reg_egress_port_3_action_read_set.execute(0);
            hdr.sflow_sample_3.pkt_length = reg_pkt_length_3_action_read_set.execute(0);
            hdr.sflow_sample_3.protocol = reg_protocol_3_action_read_set.execute(0);
            hdr.sflow_sample_3.src_ip = reg_src_ip_3_action_read_set.execute(0);
            hdr.sflow_sample_3.dst_ip = reg_dst_ip_3_action_read_set.execute(0);
            hdr.sflow_sample_3.src_port = reg_src_port_3_action_read_set.execute(0);
            hdr.sflow_sample_3.dst_port = reg_dst_port_3_action_read_set.execute(0);
            hdr.sflow_sample_3.tcp_flags = reg_tcp_flag_3_action_read_set.execute(0);
            hdr.sflow_sample_3.tos = reg_tos_3_action_read_set.execute(0);

            hdr.ipv4.total_len = (bit<16>)376;
        }

    }
}

/* Ingress Deparser*/

control MyIngressDeparser(packet_out pkt,
                            /* User */
                            inout my_header_t hdr,
                            in my_metadata_t meta,
                            /* Intrinsic */
                            in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    /* Resource Definitions */
    Checksum() ipv4_checksum;
    Checksum() udp_checksum;
    Mirror() m;
    apply {
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        if(hdr.sflow_hd.isValid()){
            if (hdr.ipv4.isValid() && hdr.udp.isValid() ) {
                    hdr.udp.checksum = udp_checksum.update({
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    8w0,
                    hdr.ipv4.protocol,
                    hdr.udp.hdr_length,
                    hdr.udp.src_port,
                    hdr.udp.dst_port,
                    hdr.udp.hdr_length,
                    16w0,              // placeholder for checksum
                    hdr.sflow_hd.version,
                    hdr.sflow_hd.address_type,
                    hdr.sflow_hd.agent_addr,
                    hdr.sflow_hd.sub_agent_id,
                    hdr.sflow_hd.sequence_number,
                    hdr.sflow_hd.uptime,
                    hdr.sflow_hd.samples,

                    hdr.sflow_sample_0.sample_type,
                    hdr.sflow_sample_0.sample_length,
                    hdr.sflow_sample_0.sample_seq_num,
                    hdr.sflow_sample_0.source_id,
                    hdr.sflow_sample_0.sampling_rate,
                    hdr.sflow_sample_0.sample_pool,
                    hdr.sflow_sample_0.drops,
                    hdr.sflow_sample_0.input_if,
                    hdr.sflow_sample_0.output_if,
                    hdr.sflow_sample_0.record_count,
                    hdr.sflow_sample_0.enterprise_format,
                    hdr.sflow_sample_0.flow_length,
                    hdr.sflow_sample_0.pkt_length,
                    hdr.sflow_sample_0.protocol,
                    hdr.sflow_sample_0.src_ip,
                    hdr.sflow_sample_0.dst_ip,
                    hdr.sflow_sample_0.src_port,
                    hdr.sflow_sample_0.dst_port,
                    hdr.sflow_sample_0.tcp_flags,
                    hdr.sflow_sample_0.tos,

                    hdr.sflow_sample_1.sample_type,
                    hdr.sflow_sample_1.sample_length,
                    hdr.sflow_sample_1.sample_seq_num,
                    hdr.sflow_sample_1.source_id,
                    hdr.sflow_sample_1.sampling_rate,
                    hdr.sflow_sample_1.sample_pool,
                    hdr.sflow_sample_1.drops,
                    hdr.sflow_sample_1.input_if,
                    hdr.sflow_sample_1.output_if,
                    hdr.sflow_sample_1.record_count,
                    hdr.sflow_sample_1.enterprise_format,
                    hdr.sflow_sample_1.flow_length,
                    hdr.sflow_sample_1.pkt_length,
                    hdr.sflow_sample_1.protocol,
                    hdr.sflow_sample_1.src_ip,
                    hdr.sflow_sample_1.dst_ip,
                    hdr.sflow_sample_1.src_port,
                    hdr.sflow_sample_1.dst_port,
                    hdr.sflow_sample_1.tcp_flags,
                    hdr.sflow_sample_1.tos,

                    hdr.sflow_sample_2.sample_type,
                    hdr.sflow_sample_2.sample_length,
                    hdr.sflow_sample_2.sample_seq_num,
                    hdr.sflow_sample_2.source_id,
                    hdr.sflow_sample_2.sampling_rate,
                    hdr.sflow_sample_2.sample_pool,
                    hdr.sflow_sample_2.drops,
                    hdr.sflow_sample_2.input_if,
                    hdr.sflow_sample_2.output_if,
                    hdr.sflow_sample_2.record_count,
                    hdr.sflow_sample_2.enterprise_format,
                    hdr.sflow_sample_2.flow_length,
                    hdr.sflow_sample_2.pkt_length,
                    hdr.sflow_sample_2.protocol,
                    hdr.sflow_sample_2.src_ip,
                    hdr.sflow_sample_2.dst_ip,
                    hdr.sflow_sample_2.src_port,
                    hdr.sflow_sample_2.dst_port,
                    hdr.sflow_sample_2.tcp_flags,
                    hdr.sflow_sample_2.tos,

                    hdr.sflow_sample_3.sample_type,
                    hdr.sflow_sample_3.sample_length,
                    hdr.sflow_sample_3.sample_seq_num,
                    hdr.sflow_sample_3.source_id,
                    hdr.sflow_sample_3.sampling_rate,
                    hdr.sflow_sample_3.sample_pool,
                    hdr.sflow_sample_3.drops,
                    hdr.sflow_sample_3.input_if,
                    hdr.sflow_sample_3.output_if,
                    hdr.sflow_sample_3.record_count,
                    hdr.sflow_sample_3.enterprise_format,
                    hdr.sflow_sample_3.flow_length,
                    hdr.sflow_sample_3.pkt_length,
                    hdr.sflow_sample_3.protocol,
                    hdr.sflow_sample_3.src_ip,
                    hdr.sflow_sample_3.dst_ip,
                    hdr.sflow_sample_3.src_port,
                    hdr.sflow_sample_3.dst_port,
                    hdr.sflow_sample_3.tcp_flags,
                    hdr.sflow_sample_3.tos
                });
            }
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.sflow_hd);
        pkt.emit(hdr.sflow_sample_0);
        pkt.emit(hdr.sflow_sample_1);
        pkt.emit(hdr.sflow_sample_2);
        pkt.emit(hdr.sflow_sample_3);
    }
}

/* Egress pipeline */

parser MyEgressParser(
        packet_in pkt,
        out my_header_t hdr,
        out my_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;
    
    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_bridge;
    }

    state parse_bridge {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control MyEgress(
        inout my_header_t hdr,
        inout my_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    action drop() {
        eg_intr_dprs_md.drop_ctl = 0b1;
    }



    apply {

 
    }
}

control MyEgressDeparser(
        packet_out pkt,
        inout my_header_t hdr,
        in my_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);

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