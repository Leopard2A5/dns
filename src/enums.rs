enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum QR {
        QUERY    = 0,
        RESPONSE = 1
    }
}

enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum OPCODE {
        QUERY  = 0,
        IQUERY = 1,
        STATUS = 2
    }
}

enum_from_primitive! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum RCODE {
        Ok              = 0,
        FormatError     = 1,
        ServerFailure   = 2,
        NameError       = 3,
        NotImplemented  = 4,
        Refused         = 5
    }
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
