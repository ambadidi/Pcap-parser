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
        let data = &pkt.data[42..];
        // println!("{:x?}", data);
        let byte_code = &data[..5];
        // println!("{:x?}", byte_code);
        let s = std::str::from_utf8(byte_code).expect("invalid utf-8 sequence");
        if s == "B6034" {
            let issue_code = &data[5..17];
            let issue_code_s = std::str::from_utf8(issue_code).expect("invalid utf-8 sequence");
            let bqty5 = &data[82..89];
            let bqty5_s = std::str::from_utf8(bqty5).expect("invalid utf-8 sequence");
            let bprice5 = &data[77..82];
            let bprice5_s = std::str::from_utf8(bprice5).expect("invalid utf-8 sequence");
            println!("{:x?} {:x?}@{:x?}", issue_code_s, bqty5_s, bprice5_s);
        }
        i += 1;
        if i == 12 {break;}
    }
}