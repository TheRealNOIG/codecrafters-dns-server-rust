use dns_starter_rust::{serialize_header, Header};
use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = test_response();
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

fn test_response() -> Vec<u8> {
    let response = Header {
        id: 1234,
        query: true,
        op_code: 0,
        authoritative_answer: false,
        truncation: false,
        recurison_desired: false,
        recursion_available: false,
        reserved: 0,
        response_code: 0,
        question_count: 0,
        answer_count: 0,
        authority_count: 0,
        additional_count: 0,
    };

    serialize_header(&response)
}

