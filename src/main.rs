use dns_starter_rust::{Header, Question, Record};
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

                let response = response(&buf[..size]).unwrap();

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

fn response(buf: &[u8]) -> Result<Vec<u8>, String> {
    let mut buffer = buf;
    let output_header: Header;
    println!("Buffer: {:?}", buffer);
    if let Ok((buf, header)) = Header::deserialize(buf) {
        output_header = Header {
            id: header.id,
            query: true,
            op_code: header.op_code,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: header.recursion_desired,
            recursion_available: false,
            reserved: 0,
            response_code: if header.op_code == 0 { 0 } else { 4 },
            question_count: 1,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
        };
        buffer = buf;
        println!("Header: {:?}", output_header);
        println!("Header: {:?}", output_header.serialize());
    } else {
        return Err("Failed to deserialize header".to_string());
    }

    let output_question: Question;
    println!("Buffer: {:?}", buffer);
    if let Ok((buf, question)) = Question::deserialize(buffer) {
        output_question = Question {
            name: question.name,
            record_type: question.record_type,
            class: question.class,
        };
        buffer = buf;
        println!("Question: {:?}", output_question);
        println!("Question: {:?}", output_question.serialize());
    } else {
        return Err("Failed to deserialize question".to_string());
    }

    let answer = Record::new(
        output_question.name.clone(),
        output_question.record_type.clone(),
        vec![8, 8, 8, 8],
        None,
    );
    println!("Answer: {:?}", answer);
    println!("Answer: {:?}", answer.serialize());

    let response = [
        output_header.serialize(),
        output_question.serialize(),
        answer.serialize(),
    ]
    .concat();
    println!("Response: {:?}", &response);
    Ok(response)
}

