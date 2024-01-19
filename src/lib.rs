// TODO: move structs to there own file (The Book pg: 119-140)
use bytes::{BufMut, BytesMut};

//Info on DNS protocol
//https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#[derive(Debug)]
pub enum RecordType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
}
impl RecordType {
    pub fn value(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub id: u16, // 16 bits                     a random id assigned to query packets. response packets must reply with the same id.
    pub query: bool, // 1 bit                   1 for a reply packet, 0 for a question packet.
    pub op_code: u8, // 4 bits                  specifies the kind of query in a message.
    pub authoritative_answer: bool, // 1 bit    1 if the responding server "owns" the domain queried, i.e., it's authoritative
    pub truncation: bool, // 1 bit              1 if the message is larger than 512 bytes. always 0 in udp responses.
    pub recurison_desired: bool, // 1 bit       sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_available: bool, // 1 bit     server sets this to 1 to indicate that recursion is available.
    pub reserved: u8, // 3 bits                 used by dnssec queries. at inception, it was reserved for future use.
    pub response_code: u8, // 4 bits            response code indicating the status of the response.
    pub question_count: u16, // 16 bits         number of questions in the question section.
    pub answer_count: u16, // 16 bits           number of records in the answer section.
    pub authority_count: u16, // 16 bits        number of records in the authority section.
    pub additional_count: u16, // 16 bits       number of records in the additional section.
}
impl Header {
    // Turns off clippy lint for concatenate |= (self.response_code as u16 & 0x0F) << 0;
    #[allow(clippy::identity_op)]
    pub fn serialize(&self) -> Vec<u8> {
        // TODO: explicitly set ints to big indian

        // Create the header buffer with a length of 12 bytes
        // 0 bytes | 12 bytes
        let mut buf = BytesMut::with_capacity(96);

        // 2 bytes | 10 bytes
        buf.put_u16(self.id);

        let mut concatenate = 0u16;
        // 1000000000000000
        concatenate |= (self.query as u16) << 15;
        // 0111100000000000
        concatenate |= (self.op_code as u16 & 0x0F) << 11;
        // 0000010000000000
        concatenate |= (self.authoritative_answer as u16) << 10;
        // 0000001000000000
        concatenate |= (self.truncation as u16) << 9;
        // 0000000100000000
        concatenate |= (self.recurison_desired as u16) << 8;
        // 0000000010000000
        concatenate |= (self.recursion_available as u16) << 7;
        // 0000000001110000
        concatenate |= (self.reserved as u16 & 0x07) << 4;
        // 0000000000001111
        concatenate |= (self.response_code as u16 & 0x0F) << 0;

        // 2 bytes | 08 bytes
        buf.put_u16(concatenate);

        // 8 bytes | 0 bytes
        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_count);
        buf.put_u16(self.authority_count);
        buf.put_u16(self.additional_count);

        buf.to_vec()
    }
}

#[derive(Debug)]
pub struct Question {
    pub name: LabelSequence, // Label Sequence  The domain name, encoded as a sequence of labels
    pub record_type: RecordType, // 2 bytes         The record type
    class: u16, //  2 bytes                     The class, in practice always set to 1 for (internet) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
}
impl Question {
    pub fn new(name: LabelSequence, record_type: RecordType) -> Question {
        Question {
            name,
            record_type,
            class: 1, // always set to 1 for (internet) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        // TODO: explicitly set ints to big indian
        // Create butter | labels 63 bytes | record type 2 bytes | class 2 bytes
        let mut buf = BytesMut::with_capacity(536);

        for (label, length) in &self.name.labels {
            buf.put_u8(*length);
            buf.put(label.as_bytes());
        }
        buf.put_u8(0);

        buf.put_u16(RecordType::value(&self.record_type));
        buf.put_u16(self.class);

        buf.to_vec()
    }
}

#[derive(Debug)]
pub struct LabelSequence {
    pub labels: Vec<(String, u8)>,
}
// Size limitations https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
impl LabelSequence {
    pub fn new(input: Vec<String>) -> Result<LabelSequence, String> {
        if input.len() > 63 {
            return Err("Exceeded maximum number of labels (63)".to_string());
        }

        let labels = input
            .into_iter()
            .map(|string| {
                if string.len() > 255 {
                    Err(format!("Name '{}' exceeds 255 octets", string))
                } else {
                    Ok((string.clone(), string.len() as u8))
                }
            })
            .collect::<Result<Vec<(String, u8)>, String>>()?;

        Ok(LabelSequence { labels })
    }
}

