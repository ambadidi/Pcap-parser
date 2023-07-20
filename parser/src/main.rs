use chrono::prelude::*;
use pcap_file::pcap::PcapReader;
use std::env;
use std::fs::File;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut pcap_file = String::new();
    let mut flag = String::new();
    if args.len() == 2 {
        pcap_file = args[1].clone();
    }
    if args.len() == 3 {
        flag = args[1].clone();
        pcap_file = args[2].clone();
    }
    let data_result = File::open(pcap_file);

    let data_file = match data_result {
        Ok(file) => file,
        Err(error) => panic!("Problem opening the data file: {:?}", error),
    };

    let mut pcap_reader = PcapReader::new(data_file).unwrap();

    let mut vec_data: Vec<Vec<String>> = Vec::new();
    for _ in 0..23 {
        vec_data.push(Vec::new());
    }
    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.unwrap().into_owned();

        let data = &pkt.data[42..];

        if data.len() < 5 {
            continue;
        }

        let byte_code = &data[..5];

        let s = match std::str::from_utf8(byte_code) {
            Ok(s) => s,
            Err(_) => {
                continue;
            }
        };
        if s == "B6034" {
            let pkt_time = pkt.timestamp;
            let nt = NaiveDateTime::from_timestamp_opt(pkt_time.as_secs() as i64, 0).unwrap();
            let dt: DateTime<Utc> = DateTime::from_utc(nt, Utc);
            let res = dt.format("%Y-%m-%d %H:%M:%S");
            vec_data[0].push(res.to_string());
            let issue_code = &data[5..17];
            let issue_code_s = std::str::from_utf8(issue_code).expect("invalid utf-8 sequence");
            vec_data[2].push(issue_code_s.to_string());
            let accept_time = &data[206..214];
            let accept_time_s = std::str::from_utf8(accept_time).expect("invalid utf-8 sequence");
            vec_data[1].push(accept_time_s.to_string());
            //bids
            let bqty5 = &data[82..89];
            let bqty5_s = std::str::from_utf8(bqty5).expect("invalid utf-8 sequence");
            vec_data[3].push(bqty5_s.to_string());
            let bprice5 = &data[77..82];
            let bprice5_s = std::str::from_utf8(bprice5).expect("invalid utf-8 sequence");
            vec_data[4].push(bprice5_s.to_string());
            let bqty4 = &data[70..77];
            let bqty4_s = std::str::from_utf8(bqty4).expect("invalid utf-8 sequence");
            vec_data[5].push(bqty4_s.to_string());
            let bprice4 = &data[65..70];
            let bprice4_s = std::str::from_utf8(bprice4).expect("invalid utf-8 sequence");
            vec_data[6].push(bprice4_s.to_string());
            let bqty3 = &data[58..65];
            let bqty3_s = std::str::from_utf8(bqty3).expect("invalid utf-8 sequence");
            vec_data[7].push(bqty3_s.to_string());
            let bprice3 = &data[53..58];
            let bprice3_s = std::str::from_utf8(bprice3).expect("invalid utf-8 sequence");
            vec_data[8].push(bprice3_s.to_string());
            let bqty2 = &data[46..53];
            let bqty2_s = std::str::from_utf8(bqty2).expect("invalid utf-8 sequence");
            vec_data[9].push(bqty2_s.to_string());
            let bprice2 = &data[41..46];
            let bprice2_s = std::str::from_utf8(bprice2).expect("invalid utf-8 sequence");
            vec_data[10].push(bprice2_s.to_string());
            let bqty1 = &data[34..41];
            let bqty1_s = std::str::from_utf8(bqty1).expect("invalid utf-8 sequence");
            vec_data[11].push(bqty1_s.to_string());
            let bprice1 = &data[29..34];
            let bprice1_s = std::str::from_utf8(bprice1).expect("invalid utf-8 sequence");
            vec_data[12].push(bprice1_s.to_string());
            //asks
            let aqty1 = &data[101..108];
            let aqty1_s = std::str::from_utf8(aqty1).expect("invalid utf-8 sequence");
            vec_data[13].push(aqty1_s.to_string());
            let aprice1 = &data[96..101];
            let aprice1_s = std::str::from_utf8(aprice1).expect("invalid utf-8 sequence");
            vec_data[14].push(aprice1_s.to_string());
            let aqty2 = &data[113..120];
            let aqty2_s = std::str::from_utf8(aqty2).expect("invalid utf-8 sequence");
            vec_data[15].push(aqty2_s.to_string());
            let aprice2 = &data[108..113];
            let aprice2_s = std::str::from_utf8(aprice2).expect("invalid utf-8 sequence");
            vec_data[16].push(aprice2_s.to_string());
            let aqty3 = &data[125..132];
            let aqty3_s = std::str::from_utf8(aqty3).expect("invalid utf-8 sequence");
            vec_data[17].push(aqty3_s.to_string());
            let aprice3 = &data[120..125];
            let aprice3_s = std::str::from_utf8(aprice3).expect("invalid utf-8 sequence");
            vec_data[18].push(aprice3_s.to_string());
            let aqty4 = &data[137..144];
            let aqty4_s = std::str::from_utf8(aqty4).expect("invalid utf-8 sequence");
            vec_data[19].push(aqty4_s.to_string());
            let aprice4 = &data[132..137];
            let aprice4_s = std::str::from_utf8(aprice4).expect("invalid utf-8 sequence");
            vec_data[20].push(aprice4_s.to_string());
            let aqty5 = &data[149..156];
            let aqty5_s = std::str::from_utf8(aqty5).expect("invalid utf-8 sequence");
            vec_data[21].push(aqty5_s.to_string());
            let aprice5 = &data[144..149];
            let aprice5_s = std::str::from_utf8(aprice5).expect("invalid utf-8 sequence");
            vec_data[22].push(aprice5_s.to_string());
        }
    }
    if flag == "-r" && !vec_data.is_empty() {
        // reorder the indices of accept time
        let mut indices: Vec<usize> = (0..vec_data[1].len()).collect();
        let accept_time_to_usize: Vec<usize> = vec_data[1]
            .iter()
            .map(|x| {
                x.parse::<usize>()
                    .expect("cannot parse to number from accept time")
            })
            .collect();
        indices.sort_by_key(|&a| accept_time_to_usize[a]);

        for i in indices {
            println!(
                "{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}",
                vec_data[0][i],
                vec_data[1][i],
                vec_data[2][i],
                vec_data[3][i],
                vec_data[4][i],
                vec_data[5][i],
                vec_data[6][i],
                vec_data[7][i],
                vec_data[8][i],
                vec_data[9][i],
                vec_data[10][i],
                vec_data[11][i],
                vec_data[12][i],
                vec_data[13][i],
                vec_data[14][i],
                vec_data[15][i],
                vec_data[16][i],
                vec_data[17][i],
                vec_data[18][i],
                vec_data[19][i],
                vec_data[20][i],
                vec_data[21][i],
                vec_data[22][i]
            );
        }
    } else if !vec_data.is_empty() {
        for i in 0..vec_data[0].len() {
            println!(
                "{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}",
                vec_data[0][i],
                vec_data[1][i],
                vec_data[2][i],
                vec_data[3][i],
                vec_data[4][i],
                vec_data[5][i],
                vec_data[6][i],
                vec_data[7][i],
                vec_data[8][i],
                vec_data[9][i],
                vec_data[10][i],
                vec_data[11][i],
                vec_data[12][i],
                vec_data[13][i],
                vec_data[14][i],
                vec_data[15][i],
                vec_data[16][i],
                vec_data[17][i],
                vec_data[18][i],
                vec_data[19][i],
                vec_data[20][i],
                vec_data[21][i],
                vec_data[22][i]
            );
        }
    }
}
