HPACK_STATIC_TABLE = (
    [":authority", ""],
    [":method", "GET"],
    [":method", "POST"],
    [":path", "/"],
    [":path", "/index.html"],
    [":scheme", "http"],
    [":scheme", "https"],
    [":status", "200"],
    [":status", "204"],
    [":status", "206"],
    [":status", "304"],
    [":status", "400"],
    [":status", "404"],
    [":status", "500"],
    ["accept-charset", ""],
    ["accept-encoding", "gzip, deflate"],
    ["accept-language", ""],
    ["accept-ranges", ""],
    ["accept", ""],
    ["access-control-allow-origin", ""],
    ["age", ""],
    ["allow", ""],
    ["authorization", ""],
    ["cache-control", ""],
    ["content-disposition", ""],
    ["content-encoding", ""],
    ["content-language", ""],
    ["content-length", ""],
    ["content-location", ""],
    ["content-range", ""],
    ["content-type", ""],
    ["cookie", ""],
    ["date", ""],
    ["etag", ""],
    ["expect", ""],
    ["expires", ""],
    ["from", ""],
    ["host", ""],
    ["if-match", ""],
    ["if-modified-since", ""],
    ["if-none-match", ""],
    ["if-range", ""],
    ["if-unmodified-since", ""],
    ["last-modified", ""],
    ["link", ""],
    ["location", ""],
    ["max-forwards", ""],
    ["proxy-authenticate", ""],
    ["proxy-authorization", ""],
    ["range", ""],
    ["referer", ""],
    ["refresh", ""],
    ["retry-after", ""],
    ["server", ""],
    ["set-cookie", ""],
    ["strict-transport-security", ""],
    ["transfer-encoding", ""],
    ["user-agent", ""],
    ["vary", ""],
    ["via", ""],
    ["www-authenticate", ""]
)


HUFFMAN_CODES = {
    b'\x00' : '1111111111000',
    b'\x01' : '11111111111111111011000',
    b'\x02' : '1111111111111111111111100010',
    b'\x03' : '1111111111111111111111100011',
    b'\x04' : '1111111111111111111111100100',
    b'\x05' : '1111111111111111111111100101',
    b'\x06' : '1111111111111111111111100110',
    b'\x07' : '1111111111111111111111100111',
    b'\x08' : '1111111111111111111111101000',
    b'\x09' : '111111111111111111101010',
    b'\x0a' : '111111111111111111111111111100',
    b'\x0b' : '1111111111111111111111101001',
    b'\x0c' : '1111111111111111111111101010',
    b'\x0d' : '111111111111111111111111111101',
    b'\x0e' : '1111111111111111111111101011',
    b'\x0f' : '1111111111111111111111101100',
    b'\x10' : '1111111111111111111111101101',
    b'\x11' : '1111111111111111111111101110',
    b'\x12' : '1111111111111111111111101111',
    b'\x13' : '1111111111111111111111110000',
    b'\x14' : '1111111111111111111111110001',
    b'\x15' : '1111111111111111111111110010',
    b'\x16' : '111111111111111111111111111110',
    b'\x17' : '1111111111111111111111110011',
    b'\x18' : '1111111111111111111111110100',
    b'\x19' : '1111111111111111111111110101',
    b'\x1a' : '1111111111111111111111110110',
    b'\x1b' : '1111111111111111111111110111',
    b'\x1c' : '1111111111111111111111111000',
    b'\x1d' : '1111111111111111111111111001',
    b'\x1e' : '1111111111111111111111111010',
    b'\x1f' : '1111111111111111111111111011',
    b'\x20' : '010100',
    b'\x21' : '1111111000',
    b'\x22' : '1111111001',
    b'\x23' : '111111111010',
    b'\x24' : '1111111111001',
    b'\x25' : '010101',
    b'\x26' : '11111000',
    b'\x27' : '11111111010',
    b'\x28' : '1111111010',
    b'\x29' : '1111111011',
    b'\x2a' : '11111001',
    b'\x2b' : '11111111011',
    b'\x2c' : '11111010',
    b'\x2d' : '010110',
    b'\x2e' : '010111',
    b'\x2f' : '011000',
    b'\x30' : '00000',
    b'\x31' : '00001',
    b'\x32' : '00010',
    b'\x33' : '011001',
    b'\x34' : '011010',
    b'\x35' : '011011',
    b'\x36' : '011100',
    b'\x37' : '011101',
    b'\x38' : '011110',
    b'\x39' : '011111',
    b'\x3a' : '1011100',
    b'\x3b' : '11111011',
    b'\x3c' : '111111111111100',
    b'\x3d' : '100000',
    b'\x3e' : '111111111011',
    b'\x3f' : '1111111100',
    b'\x40' : '1111111111010',
    b'\x41' : '100001',
    b'\x42' : '1011101',
    b'\x43' : '1011110',
    b'\x44' : '1011111',
    b'\x45' : '1100000',
    b'\x46' : '1100001',
    b'\x47' : '1100010',
    b'\x48' : '1100011',
    b'\x49' : '1100100',
    b'\x4a' : '1100101',
    b'\x4b' : '1100110',
    b'\x4c' : '1100111',
    b'\x4d' : '1101000',
    b'\x4e' : '1101001',
    b'\x4f' : '1101010',
    b'\x50' : '1101011',
    b'\x51' : '1101100',
    b'\x52' : '1101101',
    b'\x53' : '1101110',
    b'\x54' : '1101111',
    b'\x55' : '1110000',
    b'\x56' : '1110001',
    b'\x57' : '1110010',
    b'\x58' : '11111100',
    b'\x59' : '1110011',
    b'\x5a' : '11111101',
    b'\x5b' : '1111111111011',
    b'\x5c' : '1111111111111110000',
    b'\x5d' : '1111111111100',
    b'\x5e' : '11111111111100',
    b'\x5f' : '100010',
    b'\x60' : '111111111111101',
    b'\x61' : '00011',
    b'\x62' : '100011',
    b'\x63' : '00100',
    b'\x64' : '100100',
    b'\x65' : '00101',
    b'\x66' : '100101',
    b'\x67' : '100110',
    b'\x68' : '100111',
    b'\x69' : '00110',
    b'\x6a' : '1110100',
    b'\x6b' : '1110101',
    b'\x6c' : '101000',
    b'\x6d' : '101001',
    b'\x6e' : '101010',
    b'\x6f' : '00111',
    b'\x70' : '101011',
    b'\x71' : '1110110',
    b'\x72' : '101100',
    b'\x73' : '01000',
    b'\x74' : '01001',
    b'\x75' : '101101',
    b'\x76' : '1110111',
    b'\x77' : '1111000',
    b'\x78' : '1111001',
    b'\x79' : '1111010',
    b'\x7a' : '1111011',
    b'\x7b' : '111111111111110',
    b'\x7c' : '11111111100',
    b'\x7d' : '11111111111101',
    b'\x7e' : '1111111111101',
    b'\x7f' : '1111111111111111111111111100',
    b'\x80' : '11111111111111100110',
    b'\x81' : '1111111111111111010010',
    b'\x82' : '11111111111111100111',
    b'\x83' : '11111111111111101000',
    b'\x84' : '1111111111111111010011',
    b'\x85' : '1111111111111111010100',
    b'\x86' : '1111111111111111010101',
    b'\x87' : '11111111111111111011001',
    b'\x88' : '1111111111111111010110',
    b'\x89' : '11111111111111111011010',
    b'\x8a' : '11111111111111111011011',
    b'\x8b' : '11111111111111111011100',
    b'\x8c' : '11111111111111111011101',
    b'\x8d' : '11111111111111111011110',
    b'\x8e' : '111111111111111111101011',
    b'\x8f' : '11111111111111111011111',
    b'\x90' : '111111111111111111101100',
    b'\x91' : '111111111111111111101101',
    b'\x92' : '1111111111111111010111',
    b'\x93' : '11111111111111111100000',
    b'\x94' : '111111111111111111101110',
    b'\x95' : '11111111111111111100001',
    b'\x96' : '11111111111111111100010',
    b'\x97' : '11111111111111111100011',
    b'\x98' : '11111111111111111100100',
    b'\x99' : '111111111111111011100',
    b'\x9a' : '1111111111111111011000',
    b'\x9b' : '11111111111111111100101',
    b'\x9c' : '1111111111111111011001',
    b'\x9d' : '11111111111111111100110',
    b'\x9e' : '11111111111111111100111',
    b'\x9f' : '111111111111111111101111',
    b'\xa0' : '1111111111111111011010',
    b'\xa1' : '111111111111111011101',
    b'\xa2' : '11111111111111101001',
    b'\xa3' : '1111111111111111011011',
    b'\xa4' : '1111111111111111011100',
    b'\xa5' : '11111111111111111101000',
    b'\xa6' : '11111111111111111101001',
    b'\xa7' : '111111111111111011110',
    b'\xa8' : '11111111111111111101010',
    b'\xa9' : '1111111111111111011101',
    b'\xaa' : '1111111111111111011110',
    b'\xab' : '111111111111111111110000',
    b'\xac' : '111111111111111011111',
    b'\xad' : '1111111111111111011111',
    b'\xae' : '11111111111111111101011',
    b'\xaf' : '11111111111111111101100',
    b'\xb0' : '111111111111111100000',
    b'\xb1' : '111111111111111100001',
    b'\xb2' : '1111111111111111100000',
    b'\xb3' : '111111111111111100010',
    b'\xb4' : '11111111111111111101101',
    b'\xb5' : '1111111111111111100001',
    b'\xb6' : '11111111111111111101110',
    b'\xb7' : '11111111111111111101111',
    b'\xb8' : '11111111111111101010',
    b'\xb9' : '1111111111111111100010',
    b'\xba' : '1111111111111111100011',
    b'\xbb' : '1111111111111111100100',
    b'\xbc' : '11111111111111111110000',
    b'\xbd' : '1111111111111111100101',
    b'\xbe' : '1111111111111111100110',
    b'\xbf' : '11111111111111111110001',
    b'\xc0' : '11111111111111111111100000',
    b'\xc1' : '11111111111111111111100001',
    b'\xc2' : '11111111111111101011',
    b'\xc3' : '1111111111111110001',
    b'\xc4' : '1111111111111111100111',
    b'\xc5' : '11111111111111111110010',
    b'\xc6' : '1111111111111111101000',
    b'\xc7' : '1111111111111111111101100',
    b'\xc8' : '11111111111111111111100010',
    b'\xc9' : '11111111111111111111100011',
    b'\xca' : '11111111111111111111100100',
    b'\xcb' : '111111111111111111111011110',
    b'\xcc' : '111111111111111111111011111',
    b'\xcd' : '11111111111111111111100101',
    b'\xce' : '111111111111111111110001',
    b'\xcf' : '1111111111111111111101101',
    b'\xd0' : '1111111111111110010',
    b'\xd1' : '111111111111111100011',
    b'\xd2' : '11111111111111111111100110',
    b'\xd3' : '111111111111111111111100000',
    b'\xd4' : '111111111111111111111100001',
    b'\xd5' : '11111111111111111111100111',
    b'\xd6' : '111111111111111111111100010',
    b'\xd7' : '111111111111111111110010',
    b'\xd8' : '111111111111111100100',
    b'\xd9' : '111111111111111100101',
    b'\xda' : '11111111111111111111101000',
    b'\xdb' : '11111111111111111111101001',
    b'\xdc' : '1111111111111111111111111101',
    b'\xdd' : '111111111111111111111100011',
    b'\xde' : '111111111111111111111100100',
    b'\xdf' : '111111111111111111111100101',
    b'\xe0' : '11111111111111101100',
    b'\xe1' : '111111111111111111110011',
    b'\xe2' : '11111111111111101101',
    b'\xe3' : '111111111111111100110',
    b'\xe4' : '1111111111111111101001',
    b'\xe5' : '111111111111111100111',
    b'\xe6' : '111111111111111101000',
    b'\xe7' : '11111111111111111110011',
    b'\xe8' : '1111111111111111101010',
    b'\xe9' : '1111111111111111101011',
    b'\xea' : '1111111111111111111101110',
    b'\xeb' : '1111111111111111111101111',
    b'\xec' : '111111111111111111110100',
    b'\xed' : '111111111111111111110101',
    b'\xee' : '11111111111111111111101010',
    b'\xef' : '11111111111111111110100',
    b'\xf0' : '11111111111111111111101011',
    b'\xf1' : '111111111111111111111100110',
    b'\xf2' : '11111111111111111111101100',
    b'\xf3' : '11111111111111111111101101',
    b'\xf4' : '111111111111111111111100111',
    b'\xf5' : '111111111111111111111101000',
    b'\xf6' : '111111111111111111111101001',
    b'\xf7' : '111111111111111111111101010',
    b'\xf8' : '111111111111111111111101011',
    b'\xf9' : '1111111111111111111111111110',
    b'\xfa' : '111111111111111111111101100',
    b'\xfb' : '111111111111111111111101101',
    b'\xfc' : '111111111111111111111101110',
    b'\xfd' : '111111111111111111111101111',
    b'\xfe' : '111111111111111111111110000',
    b'\xff' : '11111111111111111111101110',
}

class HPACK:
    def __init__(self, maxSize: int = 4096) -> None:
        self.Dynamic_Table = []
        self.MaxSize       = maxSize
        self.Size          = 0

    ####################
    ##### PREFIXES #####
    ####################

    @staticmethod
    def EncodePrefix(num: int, prefix: str) -> bytes:
        N = 8 - len(prefix)
        p = int(prefix,2)<<N
        if num < 2**N-1:
             return (p+num).to_bytes()
        else:
             num -= 2**N-1
             res = (p+(2**N-1)).to_bytes()
             while num >= 128:
                 en = num % 128
                 en += 128
                 res += en.to_bytes()
                 num //= 128
             if num == 0:
                 res = res[:-1] + (res[-1]-128).to_bytes()
             else:
                 res += num.to_bytes()
             return res

    @staticmethod
    def DecodePrefix(enc: bytes, i: int, prefix: str) -> tuple:
        N = 8 - len(prefix)
        p = int(prefix,2)<<N
        if HPACK.IsPrefixed(enc[i], prefix):
            if enc[i] - p == 2**N-1:
                num = 2**N-1
                i+=1
                while enc[i] & 128 != 0:
                    num += (enc[i] - 128) << (7*(i-1))
                    i+=1
                num += enc[i] << (7*(i-1))
                return (num, i+1)
            else:
                return (enc[i]-p, i+1)
        else:
            raise ValueError("Prefix doesn't match")

    @staticmethod
    def IsPrefixed(enc: int, prefix: str) -> bool:
        enc_bits = f"{bin(enc)[2:]:0>8}"
        return enc_bits[:len(prefix)] == prefix

    ##################
    ## HUFFMAN CODE ##
    ##################

    @staticmethod
    def EncodeHuffman(text: str) -> bytes:
        codes = []
        for i in text:
            codes.append(HUFFMAN_CODES[i.encode()])
        enc_bits = ''.join(codes)
        enc_bits += '1' * (8-(len(enc_bits)%8))
        enc_num = int(enc_bits,2)
        enc = enc_num.to_bytes(len(enc_bits)//8)

        return enc

    @staticmethod
    def DecodeHuffman(enc: bytes) -> str:
        chars = []
        enc_num = int.from_bytes(enc)
        enc_bits = bin(enc_num)[2:]
        enc_bits = ('0' * (len(enc)*8 - len(enc_bits))) + enc_bits
        i = 0
        j = 5 # The smallest code length is 5
        while j<=len(enc_bits):
            if enc_bits[i:j] in HUFFMAN_CODES.values():
                chars.append(list(HUFFMAN_CODES.keys())[list(HUFFMAN_CODES.values()).index(enc_bits[i:j])].decode()) # Getting key from value
                i = j
                j += 5
            else:
                j+=1

        return ''.join(chars)

    ##################
    #### INDEXING ####
    ##################

    def GetIndex(self, name: str, value: str) -> bytes:
        iname = -1
        for i, j in enumerate(HPACK_STATIC_TABLE):
            if j[0] == name and j[1] == value:
                return b"\x02" + (i+1).to_bytes(1)
            elif j[0] == name and iname == -1:
                iname = i
        for i, j in enumerate(self.Dynamic_Table):
            if j[0] == name and j[1] == value:
                return b"\x02" + (i+61+1).to_bytes(1)
            elif j[0] == name and iname == -1:
                iname = i+61
        if iname != -1:
            return b"\x01" + (iname+1).to_bytes(1)
        else:
            return b"\x00\x00"

    def GetHeader(self, index: int) -> list[str]:
        return HPACK_STATIC_TABLE[index-1] if index <= 61 else self.Dynamic_Table[index-61-1]

    def IncrementTable(self, name: str, value: str) -> None:
        self.Size += len(name) + len(value) + 32
        self.Dynamic_Table.append([name,value])

    ##################
    #### ENCODING ####
    ##################

    @staticmethod
    def EncodeLiteral(text: str, huffman: bool = False) -> bytes:
        if huffman:
            enc = HPACK.EncodeHuffman(text)
            encLen = len(enc) + 128
        else:
            enc = text.encode()
            encLen = len(enc)
        return encLen.to_bytes() + enc


    def IndexedHeader(self, index: int) -> bytes:
        return HPACK.EncodePrefix(index, '1')
    def Literal_NoIndexing_IndexedName(self, index: int, value: str, huffman: bool = False) -> bytes:
        encvalue = self.EncodeLiteral(value, huffman)
        return HPACK.EncodePrefix(index, '0000') + encvalue

    def Literal_NoIndexing_NewName(self, name: str, value: str, huffman: bool = False) -> bytes:
        encname = self.EncodeLiteral(name, huffman)
        encvalue = self.EncodeLiteral(value, huffman)
        return b'\x00' + encname + encvalue

    def Literal_IncIndex_IndexedName(self, index: int, name: str, value: str, huffman: bool = False) -> bytes:
        self.IncrementTable(name, value)
        encvalue = self.EncodeLiteral(value, huffman) 
        return HPACK.EncodePrefix(index, '01') + encvalue

    def Literal_IncIndex_NewName(self, name: str, value: str, huffman: bool = False) -> bytes:
        self.IncrementTable(name, value)
        encname = self.EncodeLiteral(name, huffman)
        encvalue = self.EncodeLiteral(value, huffman)
        return b'\x40' + encname + encvalue

    def EncodeHeaders(self, headers: dict[str,str], incIndex: bool = True, huffman: bool = False) -> bytes:
        enc = b''
        for name, value in headers.items():
            if len(name) >= 128 or len(value) >= 128:
                raise ValueError("Name of Value length is too large")
            index = self.GetIndex(name, value)
            if index[0] == 2:
                enc += self.IndexedHeader(index[1])
            elif index[0] == 1:
                if incIndex:
                    enc += self.Literal_IncIndex_IndexedName(index[1], name, value, huffman)
                else:
                    enc += self.Literal_NoIndexing_IndexedName(index[1], value, huffman)
            else:
                if incIndex:
                    enc += self.Literal_IncIndex_NewName(name, value, huffman)
                else:
                    enc += self.Literal_NoIndexing_NewName(name, value, huffman)
        return enc

    ##################
    #### DECODING ####
    ##################

    def DecodeHeaders(self, enc: bytes) -> dict[str,str]:
        Headers = {}
        i = 0
        while i < len(enc):
            if HPACK.IsPrefixed(enc[i], '1'):
                # print('   1', hex(enc[i]))
                index, i = HPACK.DecodePrefix(enc, i, '1')
                name, value = self.GetHeader( index )
                Headers[name] = value
            elif HPACK.IsPrefixed(enc[i], '01'):
                # print('  01', hex(enc[i]))
                index, i = HPACK.DecodePrefix(enc, i, '01')
                if index != 0:
                    name, _ = self.GetHeader( index )
                    valLen = enc[i]
                    i+=1
                    if valLen & 128 != 0:
                        valLen &= ~128
                        value = HPACK.DecodeHuffman(enc[i:i+valLen])
                    else:
                        value = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                    self.IncrementTable(name, value)
                else:
                    nameLen = enc[i]
                    i+=1
                    if nameLen & 128 != 0:
                        nameLen &= ~128
                        name = HPACK.DecodeHuffman(enc[i:i+nameLen])
                    else:
                        name = enc[i:i+1+nameLen].decode()
                    i+=nameLen
                    valLen  = enc[i]
                    i+=1
                    if valLen & 128 != 0:
                        valLen &= ~128
                        value = HPACK.DecodeHuffman(enc[i:i+valLen])
                    else:
                        value = enc[i:i+1+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                    self.IncrementTable(name, value)
            elif HPACK.IsPrefixed(enc[i], '0000'):
                # print('0000', hex(enc[i]))
                if enc[i] != 0:
                    name, _ = self.GetHeader( enc[i] )
                    i+=1
                    valLen = enc[i]
                    i+=1
                    if valLen & 128 != 0:
                        valLen &= ~128
                        value = HPACK.DecodeHuffman(enc[i:i+valLen])
                    else:
                        value = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                else:
                    i+=1
                    nameLen = enc[i]
                    i+=1
                    if nameLen & 128 != 0:
                        nameLen &= ~128
                        name = HPACK.DecodeHuffman(enc[i:i+1+nameLen])
                    else:
                        name = enc[i:i+1+nameLen].decode()
                    i+=nameLen
                    valLen  = enc[i]
                    i+=1
                    if valLen & 128 != 0:
                        valLen &= ~128
                        value = HPACK.DecodeHuffman(enc[i:i+valLen])
                    else:
                        value = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
            else:
                raise CompressionError()

        return Headers

class CompressionError(Exception):
    def __init__(self, message: str = "Unable to Decode HPACK Headers.") -> None:
        self.message = message
        super().__init__(self.message)

if __name__ == "__main__":
    hpack = HPACK()
    print(hpack.EncodeHeaders({":method":"GET",":scheme":"https",":path":"/",":authority":"example.com","accept":"text/html","accept-language":"ru","user-agent":"CubicBrowser/9.7"}))
