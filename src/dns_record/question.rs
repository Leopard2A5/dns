#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question<'a> {
    pub labels: Vec<&'a str>,
    pub qtype: Qtype,
    pub qclass: Qclass
}

enum_from_primitive! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Qtype {
        A        =   1,
        NS       =   2,
        MD       =   3,
        MF       =   4,
        CNAME    =   5,
        SOA      =   6,
        MB       =   7,
        MG       =   8,
        MR       =   9,
        NULL     =  10,
        WKS      =  11,
        PTR      =  12,
        HINFO    =  13,
        MINFO    =  14,
        MX       =  15,
        TXT      =  16,
        AXFR     = 252,
        MAILB    = 253,
        MAILA    = 254,
        Wildcard = 255
    }
}

enum_from_primitive!{
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Qclass {
        IN          =   1,
        CS          =   2,
        CH          =   3,
        HS          =   4,
        Wildcard    = 255
    }
}
