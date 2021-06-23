use super::ipv4_header::Ipv4HeaderData;
use byteorder::{BigEndian, ByteOrder};

pub const ICMP_HEADER_LENGTH: u8 = 4;

#[derive(Debug)]
pub struct IcmpHeader<'a> {
    raw: &'a [u8],
    data: &'a IcmpHeaderData,
}

#[derive(Debug)]
pub struct IcmpHeaderMut<'a> {
    raw: &'a mut [u8],
    data: &'a mut IcmpHeaderData,
}

#[derive(Clone, Debug)]
pub struct IcmpHeaderData {
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
}

#[allow(dead_code)]
impl IcmpHeaderData {
    pub fn parse(raw: &[u8]) -> Self {
        Self {
            icmp_type: raw[0],
            icmp_code: raw[1],
            checksum: BigEndian::read_u16(&raw[2..4]),
        }
    }

    #[inline]
    pub fn bind<'c, 'a: 'c, 'b: 'c>(&'a self, raw: &'b [u8]) -> IcmpHeader<'c> {
        IcmpHeader::new(raw, self)
    }

    #[inline]
    pub fn bind_mut<'c, 'a: 'c, 'b: 'c>(&'a mut self, raw: &'b mut [u8]) -> IcmpHeaderMut<'c> {
        IcmpHeaderMut::new(raw, self)
    }

    #[inline]
    pub fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    #[inline]
    pub fn icmp_code(&self) -> u8 {
        self.icmp_code
    }
}

macro_rules! icmp_header_common {
    ($name:ident, $raw_type:ty, $data_type: ty) => {
        #[allow(dead_code)]
        impl<'a> $name<'a> {
            pub fn new(raw: $raw_type, data: $data_type) -> Self {
                Self { raw, data }
            }

            #[inline]
            pub fn raw(&self) -> &[u8] {
                self.raw
            }

            #[inline]
            pub fn data(&self) -> &IcmpHeaderData {
                self.data
            }

            #[inline]
            pub fn icmp_type(&self) -> u8 {
                self.data.icmp_type
            }

            #[inline]
            pub fn icmp_code(&self) -> u8 {
                self.data.icmp_code
            }
        }
    };
}

icmp_header_common!(IcmpHeader, &'a [u8], &'a IcmpHeaderData);
icmp_header_common!(IcmpHeaderMut, &'a mut [u8], &'a mut IcmpHeaderData);

#[allow(dead_code)]
impl<'a> IcmpHeaderMut<'a> {
    #[inline]
    pub fn raw_mut(&mut self) -> &mut [u8] {
        self.raw
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut IcmpHeaderData {
        self.data
    }

    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.data.icmp_type = icmp_type;
        self.raw[0] = icmp_type;
    }

    #[inline]
    pub fn set_icmp_code(&mut self, icmp_code: u8) {
        self.data.icmp_code = icmp_code;
        self.raw[1] = icmp_code;
    }

    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        BigEndian::write_u16(&mut self.raw[2..4], checksum);
    }

    #[inline]
    pub fn update_checksum(&mut self, ipv4_header_data: &Ipv4HeaderData, payload: &[u8]) {
        self.set_checksum(0);
        let transport_length =
            ipv4_header_data.total_length() - u16::from(ipv4_header_data.header_length());
        let end = transport_length as usize / 2;

        let mut sum = 0u32;
        let data = &[self.raw, payload].concat()[..];

        sum += (0..end)
            .map(|i| {
                let range = 2 * i..2 * (i + 1);
                u32::from(BigEndian::read_u16(&data[range]))
            })
            .sum::<u32>();

        while (sum & !0xffff) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        self.set_checksum(!sum as u16);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::BigEndian;
    use byteorder::WriteBytesExt;

    fn create_header() -> Vec<u8> {
        let mut raw = Vec::new();
        raw.reserve(8);
        raw.write_u8(0).unwrap(); // icmp type
        raw.write_u8(0).unwrap(); // icmp code
        raw.write_u16::<BigEndian>(0).unwrap(); //icmp checksum
        raw
    }

    #[test]
    fn parse_header_test() {
        let raw = &create_header()[..];
        let data = IcmpHeaderData::parse(raw);
        assert_eq!(0, data.icmp_type);
        assert_eq!(0, data.icmp_code);
    }

    #[test]
    fn edit_header_test() {
        let raw = &mut create_header()[..];
        let mut header_data = IcmpHeaderData::parse(raw);
        let mut header = header_data.bind_mut(raw);
        header.set_icmp_code(1);
        header.set_icmp_type(1);
        assert_eq!(1, header.icmp_code());
        assert_eq!(1, header.icmp_type());
        {
            let raw = header.raw();
            let raw_icmp_type = raw[0];
            let raw_icmp_code = raw[1];
            assert_eq!(1, raw_icmp_type);
            assert_eq!(1, raw_icmp_code);
        }
    }
}
