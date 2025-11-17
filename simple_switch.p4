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
    Register<bit<32>, bit<1>>(1,0) send_flag;


    action send_multicast(bit<16> grp_id, bit<16> rid) {
        ig_tm_md.mcast_grp_a = grp_id;
        ig_tm_md.rid = rid;
    }
    action set_out_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;

    }

    table ingress_port_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_out_port;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        ingress_port_forward.apply();
        bit<1>  idx0 = 0;
        bit<32> ten  = 10;
        bit<32> flag_val;
        send_flag.write(idx0, ten);   // 索引只有 0 可用
        bit<32> flag_val;
        send_flag.read(flag_val, idx0);

        if(flag_val==ten){
            if(ig_intr_md.ingress_port==140){
                bit<32> total_packet;
                total_packet = set_total_packet.execute(0);
                if(total_packet == 0){
                ig_tm_md.mcast_grp_a = 1;
                ig_tm_md.rid = 1;
                }
            } 
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

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
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
