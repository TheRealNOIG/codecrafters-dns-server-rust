use bytes::{BufMut, BytesMut};

//More info on DNS header format
//https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md
#[derive(Debug)]
pub struct Header {
    pub id: u16, // 16 bits   a random id assigned to query packets. response packets must reply with the same id.
    pub query: bool, // 1 bit     1 for a reply packet, 0 for a question packet.
    pub op_code: u8, // 4 bits    specifies the kind of query in a message.
    pub authoritative_answer: bool, // 1 bit     1 if the responding server "owns" the domain queried, i.e., it's authoritative
    pub truncation: bool, // 1 bit     1 if the message is larger than 512 bytes. always 0 in udp responses.
    pub recurison_desired: bool, // 1 bit     sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_available: bool, // 1 bit     server sets this to 1 to indicate that recursion is available.
    pub reserved: u8, // 3 bits    used by dnssec queries. at inception, it was reserved for future use.
    pub response_code: u8, // 4 bits    response code indicating the status of the response.
    pub question_count: u16, // 16 bits   number of questions in the question section.
    pub answer_count: u16, // 16 bits   number of records in the answer section.
    pub authority_count: u16, // 16 bits   number of records in the authority section.
    pub additional_count: u16, // 16 bits   number of records in the additional section.
}

// Turns off clippy lint for concatenate |= (header.response_code as u16 & 0x0F) << 0;
#[allow(clippy::identity_op)]
pub fn serialize_header(header: &Header) -> Vec<u8> {
    // Create the header buffer with a length of 12 bytes
    // 0 bytes | 12 bytes
    let mut buf = BytesMut::with_capacity(96);

    // 2 bytes | 10 bytes
    buf.put_u16(header.id);

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

    // 2 bytes | 08 bytes
    buf.put_u16(concatenate);

    // 8 bytes | 0 bytes
    buf.put_u16(header.question_count);
    buf.put_u16(header.answer_count);
    buf.put_u16(header.authority_count);
    buf.put_u16(header.additional_count);

    buf.to_vec()
}

