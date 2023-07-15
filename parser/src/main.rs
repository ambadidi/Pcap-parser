use pcap_file::pcap::PcapReader;
use std::env;
use std::fs::File;
// use std::io::prelude::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    let pcap_file = &args[1];

    
    let data_result = File::open(pcap_file);

    let data_file = match data_result {
        Ok(file) => file,
        Err(error) => panic!("Problem opening the data file: {:?}", error),
    };

    // println!("Data file: {:?}", data_file);
    let mut pcap_reader = PcapReader::new(data_file).unwrap();
    // Read test.pcap
    let mut i = 0;
    while let Some(pkt) = pcap_reader.next_packet() {
        //Check if there is no error
        let pkt = pkt.unwrap().into_owned();

        //Do something
        println!("{:?}", pkt.timestamp);
        i += 1;
        if i == 5 {break;}
    }
}
