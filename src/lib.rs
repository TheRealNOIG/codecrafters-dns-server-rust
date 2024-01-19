// TODO: move structs to there own file (The Book pg: 119-1403
use bytes::{BufMut, BytesMut};
use nom::{bytes::complete::take, number::complete::be_u16, IResult};

//Info on DNS protocol
//https://datatracker.ietf.org/doc/html/rfc1035
//https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md

#[derive(Debug)]
pub struct RecordTypeError;
impl From<RecordTypeError> for nom::Err<nom::error::Error<&[u8]>> {
    fn from(_: RecordTypeError) -> Self {
        nom::Err::Failure(nom::error::Error::new(&[], nom::error::ErrorKind::Tag))
    }
}
// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#[derive(Debug, Clone, Copy)]
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
impl TryFrom<u16> for RecordType {
    type Error = RecordTypeError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            3 => Ok(RecordType::MD),
            4 => Ok(RecordType::MF),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            7 => Ok(RecordType::MB),
            8 => Ok(RecordType::MG),
            9 => Ok(RecordType::MR),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            _ => Err(RecordTypeError),
        }
    }
}
impl RecordType {
    pub fn value(&self) -> u16 {
        *self as u16
    }
}

//https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Debug)]
pub struct Header {
    pub id: u16, // 16 bits                     a random id assigned to query packets. response packets must reply with the same id.
    pub query: bool, // 1 bit                   1 for a reply packet, 0 for a question packet.
    pub op_code: u8, // 4 bits                  specifies the kind of query in a message.
    pub authoritative_answer: bool, // 1 bit    1 if the responding server "owns" the domain queried, i.e., it's authoritative
    pub truncation: bool, // 1 bit              1 if the message is larger than 512 bytes. always 0 in udp responses.
    pub recursion_desired: bool, // 1 bit       sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
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
        concatenate |= (self.recursion_desired as u16) << 8;
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
    //https://docs.rs/nom/latest/nom/number/complete/fn.be_u16.html
    pub fn deserialize(data: &[u8]) -> IResult<&[u8], Header> {
        let (data, id) = be_u16(data)?;
        let (data, flags) = be_u16(data)?;
        let (data, question_count) = be_u16(data)?;
        let (data, answer_count) = be_u16(data)?;
        let (data, authority_count) = be_u16(data)?;
        let (data, additional_count) = be_u16(data)?;

        let query = (flags >> 15) & 0x01 != 0;
        let op_code = ((flags >> 11) & 0x0F) as u8;
        let authoritative_answer = (flags >> 10) & 0x01 != 0;
        let truncation = (flags >> 9) & 0x01 != 0;
        let recursion_desired = (flags >> 8) & 0x01 != 0;
        let recursion_available = (flags >> 7) & 0x01 != 0;
        let reserved = ((flags >> 4) & 0x07) as u8;
        let response_code = (flags & 0x0F) as u8;

        Ok((
            data,
            Header {
                id,
                query,
                op_code,
                authoritative_answer,
                truncation,
                recursion_desired,
                recursion_available,
                reserved,
                response_code,
                question_count,
                answer_count,
                authority_count,
                additional_count,
            },
        ))
    }
}

//https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
#[derive(Debug)]
pub struct Question {
    pub name: LabelSequence, // Label Sequence  The domain name, encoded as a sequence of labels
    pub record_type: RecordType, // 2 bytes         The record type
    pub class: u16, //  2 bytes                     The class, in practice always set to 1 for (internet) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
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
        // Create butter 512 < | labels 63 bytes | record type 2 bytes | class 2 bytes
        let mut buf = BytesMut::with_capacity(512);

        buf.put_slice(self.name.serialize().as_slice());

        buf.put_u16(RecordType::value(&self.record_type));
        buf.put_u16(self.class);

        buf.to_vec()
    }
    pub fn deserialize(data: &[u8]) -> IResult<&[u8], Question> {
        let (data, name) = LabelSequence::deserialize(data)?;
        let (data, record_type_num) = be_u16(data)?;
        let (data, class) = be_u16(data)?;

        let record_type = RecordType::try_from(record_type_num)?;

        Ok((
            data,
            Question {
                name,
                record_type,
                class,
            },
        ))
    }
}

//https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
#[derive(Debug, Clone)]
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

    fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);

        for (label, length) in &self.labels {
            buf.put_u8(*length);
            buf.put(label.as_bytes());
        }
        buf.put_u8(0);

        buf.to_vec()
    }
    //https://docs.rs/nom/latest/nom/bytes/complete/fn.take.html
    fn deserialize(data: &[u8]) -> IResult<&[u8], LabelSequence> {
        let mut label_sequence = LabelSequence { labels: Vec::new() };
        let mut remaining = data;

        while !remaining.is_empty() && remaining[0] != 0 {
            let (new_remaining, length) = take(1usize)(remaining)?;
            let (new_remaining, label) = take(length[0] as usize)(new_remaining)?;
            label_sequence
                .labels
                .push((String::from_utf8(label.to_vec()).unwrap(), length[0]));
            remaining = new_remaining;
        }

        // remove the last zero
        let (remaining, _) = take(1usize)(remaining)?;
        Ok((remaining, label_sequence))
    }
}

//https://datatracker.ietf.org/doc/html/rfc1035#section-3.2
#[derive(Debug)]
pub struct Record {
    pub name: LabelSequence, //an owner name, i.e., the name of the node to which this resource record pertains
    pub record_type: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub data: Vec<u8>,
}
impl Record {
    pub fn new(
        name: LabelSequence,
        record_type: RecordType,
        data: Vec<u8>,
        ttl: Option<u32>,
    ) -> Record {
        Record {
            name,
            record_type,
            class: 1, // always set to 1 for (internet) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
            ttl: ttl.unwrap_or(60),
            length: data.len() as u16,
            data,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        // Create buffer 512 < | labels 63 bytes | record type 2 bytes | class 2 bytes | ttl 4 bytes | length 2 bytes | data length
        let mut buf = BytesMut::with_capacity(512);

        buf.put_slice(self.name.serialize().as_slice());
        buf.put_u16(self.record_type.value());
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(self.length);
        buf.put_slice(&self.data);

        buf.to_vec()
    }
    pub fn deserialize(_data: &[u8]) -> IResult<&[u8], Record> {
        todo!()
    }
}

