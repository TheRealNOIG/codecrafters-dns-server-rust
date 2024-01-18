// Uncomment this block to pass the first stage
use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};

//More info on DNS header format
//https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md
#[derive(Debug)]
struct Header {
    id: u16, //16 bits   A random ID assigned to query packets. Response packets must reply with the same ID.
    query: bool, //1 bit     1 for a reply packet, 0 for a question packet.
    op_code: u8, //4 bits    Specifies the kind of query in a message.
    authoritative_answer: bool, //1 bit     1 if the responding server "owns" the domain queried, i.e., it's authoritative
    truncation: bool, //1 bit     1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    recurison_desired: bool, //1 bit     Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    recursion_available: bool, //1 bit     Server sets this to 1 to indicate that recursion is available.
    reserved: u8, //3 bits    Used by DNSSEC queries. At inception, it was reserved for future use.
    response_code: u8, //4 bits    Response code indicating the status of the response.
    question_count: u16, //16 bits   Number of questions in the Question section.
    answer_count: u16, //16 bits   Number of records in the Answer section.
    authority_count: u16, //16 bits   Number of records in the Authority section.
    additional_count: u16, //16 bits   Number of records in the Additional section.
}

fn serialize_header(header: &Header) -> Vec<u8> {
    // Create the full buffer
    // header only uses 12 bytes of the buffer
    // 0 bytes | 12 bytes
    let mut buf = BytesMut::with_capacity(512);

    // 2 bytes | 10 bytes
    buf.put_u16(header.id);

    // 2 bytes | 08 bytes
    let mut concatenate = 0u16;
    // 1000000000000000
    concatenate |= (header.query as u16) << 15;
    // 0111100000000000
    concatenate |= (header.op_code as u16 & 0x0F) << 11;
    // 0000010000000000
    concatenate |= (header.authoritative_answer as u16) << 10;
    // 0000001000000000
    concatenate |= (header.truncation as u16) << 9;
    // 0000000100000000
    concatenate |= (header.recurison_desired as u16) << 8;
    // 0000000010000000
    concatenate |= (header.recursion_available as u16) << 7;
    // 0000000001110000
    concatenate |= (header.reserved as u16 & 0x07) << 4;
    // 0000000000001111
    concatenate |= (header.response_code as u16 & 0x0F) << 0;
    buf.put_u16(concatenate);

    // 8 bytes | 0 bytes
    buf.put_u16(header.question_count);
    buf.put_u16(header.answer_count);
    buf.put_u16(header.authority_count);
    buf.put_u16(header.additional_count);

    buf.to_vec()
}

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

