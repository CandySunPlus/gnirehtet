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
pub struct IcmpHeaderData {}

#[allow(dead_code)]
impl IcmpHeaderData {
    pub fn parse(_: &[u8]) -> Self {
        Self {}
    }

    #[inline]
    pub fn bind<'c, 'a: 'c, 'b: 'c>(&'a self, raw: &'b [u8]) -> IcmpHeader<'c> {
        IcmpHeader::new(raw, self)
    }

    #[inline]
    pub fn bind_mut<'c, 'a: 'c, 'b: 'c>(&'a mut self, raw: &'b mut [u8]) -> IcmpHeaderMut<'c> {
        IcmpHeaderMut::new(raw, self)
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
}
