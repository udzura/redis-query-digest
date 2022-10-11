extern crate pcap;

use pktparse::*;
use std::error::Error;

const PCAP_HEADER_MAGIC: usize = 4;

fn main() -> Result<(), Box<dyn Error>> {
    let mut pcap = pcap::Capture::from_file("./dump.pcap")?;
    while let Ok(data) = pcap.next_packet() {
        // println!("pcap header: {:?}", data.header);
        let data = &data.data.to_owned().leak()[PCAP_HEADER_MAGIC..];
        // let (data, header) = arp::parse_arp_pkt(data)?;

        let (data, header) = ipv4::parse_ipv4_header(data)?;
        println!("src: {:?} dst: {:?}", header.source_addr, header.dest_addr);
        let (data, header) = tcp::parse_tcp_header(data)?;

        println!(
            "(urg:{:?} ack:{:?} psh:{:?} rst:{:?} syn:{:?} fin:{:?})\n(seq: {}),src port: {:?}, dst port: {:?}",
            header.flag_urg,
            header.flag_ack,
            header.flag_psh,
            header.flag_rst,
            header.flag_syn,
            header.flag_fin,
	    header.sequence_no,
            header.source_port,
            header.dest_port
        );

        let body = String::from_utf8_lossy(data);
        println!("body:\n{}", body);
        println!("----");

        drop(data);
    }
    return Ok(());
}
