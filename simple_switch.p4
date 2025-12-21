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
            RECIRC_PORT: parse_sample;   // 從 recirc port 進來
            default   : parse_ethernet;      // 一般 front-panel port
        }
    }

    state parse_sample {
        // pkt.extract(hdr.sample);
        pkt.extract(hdr.sample);
        meta.sample_ing_port = (bit<32>)hdr.sample.ingress_port;
        meta.sampling_rate = (bit<32>)hdr.sample.sampling_rate;
        transition parse_raw_128;  // 接著去 parse_raw_128
    }

    state parse_raw_128 {
        pkt.extract(hdr.raw_128);   // 直接吃 128 bytes
        meta.raw_128_data = (bit<1024>)hdr.raw_128.data;
        transition accept;
    }
   

    state parse_ethernet {
        // pkt.advance(PORT_METADATA_SIZE);
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
    action set_ts(bit<32> ts) {
        meta.ctrl_ts = ts;          // 把 action 參數寫進 metadata
    }
    action set_sample_hd(bit<32> agent_addr,bit<32> agent_id) {
        hdr.ethernet.src_addr = 0x001122334455;
        hdr.ethernet.dst_addr = 0x001b21bcaad3;
        hdr.ethernet.ether_type = 0x0800;
        hdr.ipv4.version=4;
        hdr.ipv4.ihl=0x45;
        hdr.ipv4.diffserv     = 0;
        hdr.ipv4.total_len = 248;
        hdr.ipv4.identification = 0; 
        hdr.ipv4.flags        = 2;
        hdr.ipv4.frag_offset  = 0; 
        hdr.ipv4.ttl          = 64;
        hdr.ipv4.protocol     = 17; 
        hdr.ipv4.src_addr = 0x0a0a0308;
        hdr.ipv4.dst_addr = 0x0a0a0303;
        
        hdr.udp.src_port = (bit<16>)8888;
        hdr.udp.dst_port = (bit<16>)6343;
        hdr.udp.hdr_length = (bit<16>)228;
        

        hdr.sflow_hd.setValid();
        hdr.sflow_hd.version = (bit<32>)5;
        hdr.sflow_hd.address_type = (bit<32>)1;
        hdr.sflow_hd.agent_addr = (bit<32>)agent_addr;
        hdr.sflow_hd.sub_agent_id = (bit<32>)agent_id;
        hdr.sflow_hd.sequence_number = (bit<32>)5;
        hdr.sflow_hd.uptime = (bit<32>)meta.ctrl_ts;
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
    table set_port_agent {
        key = {
            hdr.sample.ingress_port : exact;
        }
        actions = {
            set_sample_hd;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
    table t_set_ts {
        key = { }                   // ★ 沒有 key → 不用 match，只有 default / 單一 entry
        actions = {
            set_ts;
            NoAction;
        }
        size = 1;
    }
    apply {
        t_set_ts.apply();
        bit<9> idx = (bit<9>)ig_intr_md.ingress_port;
        if(ig_intr_md.ingress_port == 36){
            hdr.ethernet.setValid();
            hdr.ipv4.setValid();
            hdr.udp.setValid();
            ig_dprsr_md.mirror_type  =0;
            // ig_tm_md.ucast_egress_port = 142;
            if (meta.sample_ing_port == 140) {
                ig_tm_md.ucast_egress_port = 142;
            }else{
                ig_tm_md.ucast_egress_port = 38;
            }
            hdr.sflow_sample.setValid();
            hdr.sflow_sample.sample_type = (bit<32>)1;
            hdr.sflow_sample.sample_length = (bit<32>)184;
            hdr.sflow_sample.sample_seq_num = (bit<32>)1;
            hdr.sflow_sample.source_id = (bit<32>)meta.sample_ing_port;
            hdr.sflow_sample.sampling_rate = (bit<32>)meta.sampling_rate;
            hdr.sflow_sample.sample_pool = (bit<32>)1;
            hdr.sflow_sample.drops = (bit<32>)0;
            hdr.sflow_sample.input_if = (bit<32>)meta.sample_ing_port;
            hdr.sflow_sample.output_if = (bit<32>)0;
            hdr.sflow_sample.record_count = (bit<32>)1;
            
            hdr.raw_record.setValid();
            hdr.raw_record.record_type = (bit<32>)1;
            hdr.raw_record.record_length = (bit<32>)144;
            hdr.raw_record.header_protocol = (bit<32>)1;
            hdr.raw_record.frame_length = (bit<32>)558;
            hdr.raw_record.payload_removed = (bit<32>)4;
            hdr.raw_record.header_length = (bit<32>)128;
            hdr.raw_record.header_bytes = (bit<1024>)meta.raw_128_data;
            
            set_port_agent.apply();
            // // hdr.sample.setInvalid();
            
        }        
        else{
            hdr.sample.setValid();
            ingress_port_forward.apply();
            port_sampling_rate.apply();
            if(ig_intr_md.ingress_port == 320){
                ig_tm_md.ucast_egress_port = 142;
            }
            bit<32> pkt_count;
            
            if(idx==140 || idx == 143){
                pkt_count = inc_pkt.execute(idx);
                if(pkt_count==0){   //送往recirc port
                    ig_dprsr_md.mirror_type = MIRROR_TYPE_t.I2E;
                    meta.mirror_session = (bit<10>)26;
                    hdr.sample.setValid();
                    // hdr.sample.magic = 0xABCD;
                    
                    hdr.sample.ingress_port = (bit<32>)ig_intr_md.ingress_port;
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
    Mirror() mirror;
    Resubmit() resubmit;
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

                    hdr.raw_record.record_type,
                    hdr.raw_record.record_length,
                    hdr.raw_record.header_protocol,
                    hdr.raw_record.frame_length,
                    hdr.raw_record.payload_removed,
                    hdr.raw_record.header_length,
                    hdr.raw_record.header_bytes
                });
            }
        }
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_t.I2E) {
        // 先把 mirror copy 丟出去，並在 mirror copy 前面 prepend sample_t
        mirror.emit<sample_t>(meta.mirror_session, hdr.sample);
    }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.sflow_hd);
        pkt.emit(hdr.sflow_sample);
        pkt.emit(hdr.raw_record);
        // if (ig_dprsr_md.mirror_type == MIRROR_TYPE_t.I2E) {
        //     mirror.emit<sample_t>(meta.mirror_session,{(bit<32>)hdr.sample.sampling_rate, (bit<32>)hdr.sample.ingress_port });
        // }
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
        // eg_intr_md.egress_port=39;
    //     if (eg_intr_dprs_md.mirror_type !=0){
    //         hdr.sample.setValid();
    //         hdr.ethernet.src_addr = 0xaaaaaaaaaaaa;
    //     }else{
    //         hdr.sample.setInvalid();
    //     }
    }
}

control MyEgressDeparser(
        packet_out pkt,
        inout my_header_t hdr,
        in my_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {

    apply {
        // pkt.emit(hdr.sample);
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
