use std::fs::File;
use std::env;
// use std::io::prelude::*;
//mdf-kospi200.20110216-0.pcap
fn main() {
    let args: Vec<String> = env::args().collect();
    let pcap_file = &args[1];
    // Open a file in read only mode in the local file system
    // let data_result = File::open("../../mdf-kospi200.20110216-0.pcap");
    let data_result = File::open(pcap_file);
    // Reading a file returns a Result enum
    // Result can be a file or an error
    let data_file = match data_result {
        Ok(file) => file,
        Err(error) => panic!("Problem opening the data file: {:?}", error),
    };

    println!("Data file: {:?}", data_file);
}
