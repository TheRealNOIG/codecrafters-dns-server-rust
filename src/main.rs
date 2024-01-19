use dns_starter_rust::{Header, LabelSequence, Question, Record, RecordType};
use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                println!("Data: {}", String::from_utf8_lossy(&buf));

                print!("Data: ");
                for byte in &buf[..size] {
                    print!("{:02x} ", byte);
                }
                println!(); // Add a newline after printing all bytes

                let response = test_response().unwrap();
                println!("Response HAUKRSATKSrAKTEKST: {:?}", response);
                // TODO: check if response is over 512 bytes and truncate it if so
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn test_response() -> Result<Vec<u8>, String> {
    let header = Header {
        id: 1234,
        query: true,
        op_code: 0,
        authoritative_answer: false,
        truncation: false,
        recurison_desired: false,
        recursion_available: false,
        reserved: 0,
        response_code: 0,
        question_count: 1,
        answer_count: 1,
        authority_count: 0,
        additional_count: 0,
    };
    println!("Header: {:?}", header);
    println!("Header: {:?}", header.serialize());

    let label_sequence = LabelSequence::new(vec!["codecrafters".to_string(), "io".to_string()])?;

    let question = Question::new(label_sequence.clone(), RecordType::A);
    println!("Question: {:?}", question);
    println!("Question: {:?}", question.serialize());

    let answer = Record::new(
        label_sequence.clone(),
        RecordType::A,
        vec![8, 8, 8, 8],
        None,
    );
    println!("Answer: {:?}", answer);
    println!("Answer: {:?}", answer.serialize());

    let response = [header.serialize(), question.serialize(), answer.serialize()].concat();
    println!("Response: {:?}", &response);
    Ok(response)
}

