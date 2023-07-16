use pcap_file::pcap::PcapReader;
use std::env;
use std::fs::File;
use chrono::prelude::*;


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
            let pkt_time = pkt.timestamp;
            let nt = NaiveDateTime::from_timestamp_opt(pkt_time.as_secs() as i64, 0).unwrap();
            let dt: DateTime<Utc> = DateTime::from_utc(nt, Utc);
            let res = dt.format("%Y-%m-%d %H:%M:%S");
            let issue_code = &data[5..17];
            let issue_code_s = std::str::from_utf8(issue_code).expect("invalid utf-8 sequence");
            let accept_time = &data[206..214];
            let accept_time_s = std::str::from_utf8(accept_time).expect("invalid utf-8 sequence");
            //bids
            let bqty5 = &data[82..89];
            let bqty5_s = std::str::from_utf8(bqty5).expect("invalid utf-8 sequence");
            let bprice5 = &data[77..82];
            let bprice5_s = std::str::from_utf8(bprice5).expect("invalid utf-8 sequence");
            let bqty4 = &data[70..77];
            let bqty4_s = std::str::from_utf8(bqty4).expect("invalid utf-8 sequence");
            let bprice4 = &data[65..70];
            let bprice4_s = std::str::from_utf8(bprice4).expect("invalid utf-8 sequence");
            let bqty3 = &data[58..65];
            let bqty3_s = std::str::from_utf8(bqty3).expect("invalid utf-8 sequence");
            let bprice3 = &data[53..58];
            let bprice3_s = std::str::from_utf8(bprice3).expect("invalid utf-8 sequence");
            let bqty2 = &data[46..53];
            let bqty2_s = std::str::from_utf8(bqty2).expect("invalid utf-8 sequence");
            let bprice2 = &data[41..46];
            let bprice2_s = std::str::from_utf8(bprice2).expect("invalid utf-8 sequence");
            let bqty1 = &data[34..41];
            let bqty1_s = std::str::from_utf8(bqty1).expect("invalid utf-8 sequence");
            let bprice1 = &data[29..34];
            let bprice1_s = std::str::from_utf8(bprice1).expect("invalid utf-8 sequence");
            //asks
            let aqty1 = &data[101..108];
            let aqty1_s = std::str::from_utf8(aqty1).expect("invalid utf-8 sequence");
            let aprice1 = &data[96..101];
            let aprice1_s = std::str::from_utf8(aprice1).expect("invalid utf-8 sequence");
            let aqty2 = &data[101..108];
            let aqty2_s = std::str::from_utf8(aqty2).expect("invalid utf-8 sequence");
            let aprice2 = &data[108..113];
            let aprice2_s = std::str::from_utf8(aprice2).expect("invalid utf-8 sequence");
            let aqty3 = &data[113..120];
            let aqty3_s = std::str::from_utf8(aqty3).expect("invalid utf-8 sequence");
            let aprice3 = &data[120..125];
            let aprice3_s = std::str::from_utf8(aprice3).expect("invalid utf-8 sequence");
            let aqty4 = &data[125..132];
            let aqty4_s = std::str::from_utf8(aqty4).expect("invalid utf-8 sequence");
            let aprice4 = &data[132..137];
            let aprice4_s = std::str::from_utf8(aprice4).expect("invalid utf-8 sequence");
            let aqty5 = &data[137..144];
            let aqty5_s = std::str::from_utf8(aqty5).expect("invalid utf-8 sequence");
            let aprice5 = &data[144..149];
            let aprice5_s = std::str::from_utf8(aprice5).expect("invalid utf-8 sequence");
            println!("{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}", res, accept_time_s, issue_code_s, bqty5_s, bprice5_s, bqty4_s, bprice4_s, bqty3_s, bprice3_s, bqty2_s, bprice2_s, bqty1_s, bprice1_s, aqty1_s, aprice1_s, aqty2_s, aprice2_s, aqty3_s, aprice3_s, aqty4_s, aprice4_s, aqty5_s, aprice5_s);
        }
        i += 1;
        if i == 12 {break;}
    }
}