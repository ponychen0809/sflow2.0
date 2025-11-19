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
const bit<9> RECIRC_PORT = 36;
parser MyIngressParser(packet_in pkt,
                out my_header_t hdr,
                out my_metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
            RECIRC_PORT: parse_sample_hdr;   // 從 recirc port 進來
            default   : parse_ethernet;      // 一般 front-panel port
        }
    }

    state parse_sample_hdr {
        pkt.extract(hdr.sample);

        transition parse_ethernet;  // 接著一樣去 parse_ethernet
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

    Register<bit<32>, bit<9>>(512, 0) port_rx_pkts;
    RegisterAction<bit<32>, bit<9>,bit<32>>(port_rx_pkts) 
        inc_pkt = {
            void apply(inout bit<32> v, out bit<32> new_val) {
                if (v == (bit<32>)hdr.sample.sampling_rate){
                    v = 0;
                }else{
                    v       = v + 1;
                }
                new_val = v; 
            }
    };
    RegisterAction<bit<32>, bit<9>, bit<32>>(port_rx_pkts) 
        read_pkt = {
            void apply(inout bit<32> v, out bit<32> new_val) {
                new_val = v; 
            }
    };

    action send_multicast(bit<16> grp_id, bit<16> rid) {
        ig_tm_md.mcast_grp_a = grp_id;
        ig_tm_md.rid = rid;
    }
    action set_out_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    action set_sampling_rate(bit<32> sampling_rate) {
        hdr.sample.sampling_rate=sampling_rate;
    }
    action set_sample_hd() {
        hdr.ipv4.total_len = (bit<16>)136;
        hdr.udp.dst_port = (bit<16>)6343;
        hdr.udp.hdr_length = (bit<16>)116;
        hdr.ipv4.dst_addr = 0x0a0a0303;
        
        hdr.sflow_hd.setValid();
        hdr.sflow_hd.version = (bit<32>)5;
        hdr.sflow_hd.address_type = (bit<32>)1;
        hdr.sflow_hd.agent_addr = (bit<32>)1;
        hdr.sflow_hd.sub_agent_id = (bit<32>)1;
        hdr.sflow_hd.sequence_number = (bit<32>)5;
        hdr.sflow_hd.uptime = (bit<32>)12345;
        hdr.sflow_hd.samples = (bit<32>)1;  
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

    table port_sampling_rate {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_sampling_rate;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        ingress_port_forward.apply();
        port_sampling_rate.apply();

        bit<9> idx = (bit<9>)ig_intr_md.ingress_port;
        bit<32> pkt_count;
        hdr.sample.setInvalid();
        if(idx==140 || idx == 143){
            pkt_count = inc_pkt.execute(idx);
            if(pkt_count==0){
                hdr.sample.setValid();
                hdr.sample.ingress_port =  (bit<32>)idx;
                ig_tm_md.mcast_grp_a = 1; 
                ig_tm_md.rid = 1;
            }
        }
        if(idx == 36){
            hdr.sample.setInvalid();
            ig_tm_md.ucast_egress_port = 142;
            
            hdr.sflow_sample.setValid();
            hdr.sflow_sample.sample_type = (bit<32>)1;
            hdr.sflow_sample.sample_length = (bit<32>)80;
            hdr.sflow_sample.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample.source_id = (bit<32>)1;
            hdr.sflow_sample.sampling_rate = (bit<32>)hdr.sample.sampling_rate;
            hdr.sflow_sample.sample_pool = (bit<32>)1;
            hdr.sflow_sample.drops = (bit<32>)0;
            hdr.sflow_sample.record_count = (bit<32>)1;
            hdr.sflow_sample.enterprise_format = (bit<32>)1;
            hdr.sflow_sample.flow_length = (bit<32>)32;

            hdr.sflow_sample.input_if = (bit<32>)hdr.sample.ingress_port;
            hdr.sflow_sample.output_if = (bit<32>)0;
            hdr.sflow_sample.pkt_length = (bit<32>)hdr.ipv4.total_len;
            hdr.sflow_sample.protocol = (bit<32>)hdr.ipv4.protocol;
            hdr.sflow_sample.src_ip = (bit<32>)hdr.ipv4.src_addr;
            hdr.sflow_sample.dst_ip = (bit<32>)hdr.ipv4.dst_addr;
            hdr.sflow_sample.src_port = (bit<32>)hdr.udp.src_port;
            hdr.sflow_sample.dst_port = (bit<32>)hdr.udp.dst_port;
            hdr.sflow_sample.tcp_flags = (bit<32>)0;
            hdr.sflow_sample.tos = (bit<32>)hdr.ipv4.diffserv;
            set_sample_hd();
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

                    hdr.sflow_sample.sample_type,
                    hdr.sflow_sample.sample_length,
                    hdr.sflow_sample.sample_seq_num,
                    hdr.sflow_sample.source_id,
                    hdr.sflow_sample.sampling_rate,
                    hdr.sflow_sample.sample_pool,
                    hdr.sflow_sample.drops,
                    hdr.sflow_sample.input_if,
                    hdr.sflow_sample.output_if,
                    hdr.sflow_sample.record_count,
                    hdr.sflow_sample.enterprise_format,
                    hdr.sflow_sample.flow_length,
                    hdr.sflow_sample.pkt_length,
                    hdr.sflow_sample.protocol,
                    hdr.sflow_sample.src_ip,
                    hdr.sflow_sample.dst_ip,
                    hdr.sflow_sample.src_port,
                    hdr.sflow_sample.dst_port,
                    hdr.sflow_sample.tcp_flags,
                    hdr.sflow_sample.tos
                });
            }
        }
        pkt.emit(hdr.sample);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.sflow_hd);
        pkt.emit(hdr.sflow_sample);
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
