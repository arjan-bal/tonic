use bytes::{Buf, BufMut, Bytes};
use tonic::{
    codec::{Codec, Decoder, EncodeBuf, Encoder},
    Status,
};

#[derive(Debug)]
pub struct BytesEncoder {}

impl Encoder for BytesEncoder {
    type Item = Bytes;

    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        dst.put_slice(&item);
        Ok(())
    }
}

#[derive(Debug)]
pub struct BytesDecoder {}

impl Decoder for BytesDecoder {
    type Item = Bytes;

    type Error = Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        // If there are no bytes to decode, return None.
        if src.remaining() == 0 {
            return Ok(None);
        }
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}

#[derive(Debug, Default)]
pub struct BytesCodec {}

impl Codec for BytesCodec {
    type Encode = Bytes;

    type Decode = Bytes;

    type Encoder = BytesEncoder;

    type Decoder = BytesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        BytesEncoder {}
    }

    fn decoder(&mut self) -> Self::Decoder {
        BytesDecoder {}
    }
}
