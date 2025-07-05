from enum import Enum
from pathlib import Path
import os
import hashlib
from datetime import datetime, timezone
sha1 = hashlib.sha1()

CWD = Path.cwd().as_posix() + '/'
DATEFORMAT = "%a, %d %b %Y %H:%M:%S %Z"
CODES = {
        200: "OK",
        204: "No Content",
        206: "Partial Content",
        304: "Not Modified",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Not Allowed",
        412: "Precondition Failed",
        414: "URI Too Long",
        505: "HTTP Version Not Supported",
}
BOUNDARY = "SUper==SigMaCubicB04ndary97"
ETagDB = Path('.ETags')
ETagDB.touch()
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

class HTTP:
    def __init__(self, raw: str|None = None) -> None:
        self.StartLine: list = []
        self.Headers:   dict = {}
        self.Body:     bytes = b""
        if type(raw) == str:
            raw_lines = raw.replace('\r','').split('\n')

            self.StartLine = raw_lines[0].split(' ')
            if len(self.StartLine) != 3:
                raise ValueError("Not valid HTTP Request")
            raw_lines.pop(0)

            keyNval = raw_lines[0].split(': ')
            while len(keyNval) == 2:
                self.SetHeader(keyNval[0], keyNval[1])
                raw_lines.pop(0)
                keyNval = raw_lines[0].split(': ')

            raw_lines.pop(0)
            self.Body = '\r\n'.join(raw_lines).encode()
        else:
            self.StartLine = ["HTTP/1.1", "", ""]

            self.SetHeader(  "Date"             ,   datetime.now(timezone.utc).strftime(DATEFORMAT)  )
            self.SetHeader(  "Connection"       ,   "keep-alive"                                     )
            self.SetHeader(  "Keep-Alive"       ,   ""                                               )
            self.SetHeader(  "Cache-Control"    ,   "public, max-age=86400"                          )
            self.SetHeader(  "X-Powered-By"     ,   "A97 the Cube"                                   )
            self.SetHeader(  "Accept-Ranges"    ,   "bytes"                                          )
            self.SetHeader(  "Content-Type"     ,   ""                                               )
            self.SetHeader(  "Content-Range"    ,   ""                                               )
            self.SetHeader(  "Content-Length"   ,   ""                                               )

    def CalculateLength(self) -> None:
        self.SetHeader("Content-Length", str(len( self.Body )))

    def SetHeader(self, header: str, value: str) -> None:
        self.Headers[header] = value

    def GetHeader(self, header: str) -> str:
        try:
            return self.Headers[header]
        except:
            return ""

    def StatusCode(self, code: int) -> None:
        if self.StartLine[0] == "HTTP/1.1":
            self.StartLine[1],self.StartLine[2] = str(code),CODES[code]
        else:
            raise TypeError("Can't assign Status Code to HTTP Request. It's for Response only")

    def _GenerateETag(self, path: Path) -> str:
        sha1.update(path.read_bytes())
        return sha1.hexdigest()

    def GetETag(self, path: Path) -> str:
        # ETags database contains ETags in format '<Relative path to file> <Last Modified Time> <ETag>'
        etags = ETagDB.read_text().split('\n')
        relpath = path.as_posix().replace(CWD, '') 
        modtime = str(os.path.getmtime(path.as_posix()))
        for i in range(len(etags)): 
            info = etags[i].split(' ')
            if info[0] == relpath: # Check if there's info about file we need in ETags database
                if info[1] == modtime: # Check if info is valid
                    return info[2]
                else:
                    # Update info if it's invalid
                    info[1] = modtime
                    info[2] = self._GenerateETag(path)
                    etags[i] = ' '.join(info)
                    ETagDB.write_text('\n'.join(etags))
                    return info[1]
        # If there's no info about the file, create it
        newETag = self._GenerateETag(path)
        etags.append(f"{relpath} {modtime} {newETag}")
        ETagDB.write_text('\n'.join(etags))
        return newETag

    def GetRange(self, body: bytes, rng: list[str]) -> bytes:
        if len(rng) != 2:
            raise ValueError("Invalid range given")
        try:
            i_rng = list(map(int, rng))
            return body[ i_rng[0] : i_rng[1] ] 
        except ValueError as e:
            if rng[0] == '' and rng[1] == '':
                raise ValueError("Invalid range given")
            elif rng[0] == '':
                return body[             : int(rng[1]) ]
            elif rng[1] == '':
                return body[ int(rng[0]) :             ]
            else:
                raise e

    def SetBody(self, body: str|bytes) -> None:
        if type(body) == str:
            self.Body = body.encode()
        elif type(body) == bytes:
            self.Body = body
        else:
            raise TypeError(f"Can't assing Body of type '{type(body)}' to HTTP Body")

    def GetBody(self, path: Path, ranges_header: str = '', boundary: str = BOUNDARY) -> None:
        print(ranges_header)
        body = path.read_bytes()
        self.SetHeader("ETag", self.GetETag(path))

        if ranges_header != '' and ranges_header.split('=')[0] == 'bytes':
            self.StatusCode(206)
            ranges = ranges_header.split('=')[1].split(',')
            print(ranges)
            if len(ranges) == 1:
                rng = ranges[0].split('-')
                self.SetHeader("Content-Range", f"bytes {ranges[0]}/{len(body)}")
                self.SetBody(self.GetRange(body, rng))
            else:
                filetype = self.GetHeader("Content-Type")
                self.SetHeader("Content-Type", f"multipart/byteranges; boundary={boundary}")
                rangesBody = b""
                separator = f"--{boundary}\r\n"
                endline = f"--{boundary}--"
                
                for rng in ranges:
                    rng = rng.split('-')
                    rangeHeaders = f"{separator}Content-Type: {filetype}\r\nContent-Range: bytes {'-'.join(rng)}/{len(body)}\r\n\r\n"
                    rangesBody += rangeHeaders.encode() + self.GetRange(body, rng) + b"\r\n"
                rangesBody += endline.encode()
                self.SetBody(rangesBody)
        else:
            self.SetBody(body)

        self.CalculateLength()

    def Raw(self) -> str:
        raw_lines = [' '.join(self.StartLine)]
        for i in self.Headers.keys():
            if self.GetHeader(i) != "":
                raw_lines.append(f"{i}: {self.GetHeader(i)}")
        raw_lines.append('')
        if self.GetHeader("Content-Type").split('/')[0] == 'text':
            raw_lines.append(self.Body.decode())
        elif len(self.Body) > 0:
            raw_lines.append(f"[{self.GetHeader('Content-Length')} Bytes of data]")

        raw = '\r\n'.join(raw_lines)
        return raw

    def RawBytes(self) -> bytes:
        raw_lines = [' '.join(self.StartLine)]
        for i in self.Headers.keys():
            if self.GetHeader(i) != "":
                raw_lines.append(f"{i}: {self.GetHeader(i)}")
        raw_lines.append('')
        raw = '\r\n'.join(raw_lines)

        raw_bytes = raw.encode()
        if type(self.Body) == str: self.Body = self.Body.encode()
        raw_bytes += b"\r\n" + self.Body
        return raw_bytes

    def __str__(self) -> str:
        return self.Raw()

class H2FrameType(Enum):
    DATA            = 0x00
    HEADERS         = 0x01
    RST_STEAM       = 0x03
    SETTINGS        = 0x04
    PUSH_PROMISE    = 0x05
    PING            = 0x06
    GOAWAY          = 0x07
    WINDOW_UPDATE   = 0x08
    CONTINUATION    = 0x09

class H2Settings(Enum):
    HEADER_TABLE_SIZE                = 0x01
    ENABLE_PUSH                      = 0x02
    MAX_CONCURENT_STREAMS            = 0x03
    INITIAL_WINDOW_SIZE              = 0x04
    MAX_FRAME_SIZE                   = 0x05
    MAX_HEADER_LIST_SIZE             = 0x06
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08
    SETTINGS_NO_RFC7540_PRIORITIES   = 0x09
    TLS_RENEG_PERMITTED              = 0x10
    SETTINGS_ENABLE_METADATA         = 0x4d44

class H2ErrorCode(Enum):
    NO_ERROR            = 0x00
    PROTOCOL_ERROR      = 0x01
    INTERNAL_ERROR      = 0x02
    FLOW_CONTROL_ERROR  = 0x03
    SETTINGS_TIMEOUT    = 0x04
    STREAM_CLOSED       = 0x05
    FRAME_SIZE_ERROR    = 0x06
    REFUSED_STREAM      = 0x07
    CANCEL              = 0x08
    COMPRESSION_ERROR   = 0x09
    CONNECT_ERROR       = 0x0A
    ENHANCE_YOUR_CALM   = 0x0B
    INADEQUATE_SECURITY = 0x0C
    HTTP_1_1_REQUIRED   = 0x0D

class H2Flag(Enum):
    END_STREAM  = 0b00000001
    ACK         = 0b00000001
    END_HEADERS = 0b00000100
    PADDED      = 0b00001000

class HPACK:
    def __init__(self, maxSize: int = 4096) -> None:
        self.Dynamic_Table = []
        self.MaxSize       = maxSize
        self.Size          = 0

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
                iname = i
        if iname != -1:
            return b"\x01" + (iname+61+1).to_bytes(1)
        else:
            return b"\x00\x00"

    def GetHeader(self, index: int) -> list[str]:
        return HPACK_STATIC_TABLE[index-1] if index <= 61 else self.Dynamic_Table[index-61-1]

    def IncrementTable(self, name: str, value: str) -> None:
        self.Dynamic_Table.append([name,value])
        self.Size += len(name) + len(value) + 32

    # Encoding
    def IndexedHeader(self, index: int) -> bytes:
        return (0x80 + index).to_bytes(1)
    def Literal_NoIndexing_IndexedName(self, index: int, value: str) -> bytes:
        return index.to_bytes(1) + len(value).to_bytes(1) + value.encode()
    def Literal_NoIndexing_NewName(self, name: str, value: str) -> bytes:
        return b'\x00' + len(name).to_bytes(1) + name.encode() + len(value).to_bytes(1) + value.encode()
    def Literal_IncIndex_IndexedName(self, index: int, name: str, value: str) -> bytes:
        self.IncrementTable(name, value)
        return (0x40 + index).to_bytes(1) + len(value).to_bytes(1) + value.encode()
    def Literal_IncIndex_NewName(self, name: str, value: str) -> bytes:
        self.IncrementTable(name, value)
        return b'\x40' + len(name).to_bytes(1) + name.encode() + len(value).to_bytes(1) + value.encode()

    def Encode(self, headers: dict[str,str], incIndex: bool = True) -> bytes:
        enc = b''
        for name, value in headers.items():
            index = self.GetIndex(name, value)
            if index[0] == 2:
                enc += self.IndexedHeader(index[1])
            elif index[0] == 1:
                if incIndex:
                    enc += self.Literal_IncIndex_IndexedName(index[1], name, value)
                else:
                    enc += self.Literal_NoIndexing_IndexedName(index[1], value)
            else:
                if incIndex:
                    enc += self.Literal_IncIndex_NewName(name, value)
                else:
                    enc += self.Literal_NoIndexing_NewName(name, value)
        return enc

    # Decoding
    def Decode(self, enc: bytes) -> dict[str,str]:
        Headers = {}
        i = 0
        while i < len(enc):
            if enc[i] & 0x80 != 0:
                name, value = self.GetHeader( enc[i] & ~0x80 )
                Headers[name] = value
                i+=1
            elif enc[i] & 0x40 != 0:
                if enc[i] & ~0x40 != 0:
                    name, _ = self.GetHeader( enc[i] & ~0x40 )
                    i+=1
                    valLen = enc[i]
                    i+=1
                    value = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                    self.IncrementTable(name, value)
                else:
                    i+=1
                    nameLen = enc[i]
                    i+=1
                    name    = enc[i:i+nameLen].decode()
                    i+=nameLen
                    valLen  = enc[i]
                    i+=1
                    value   = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                    self.IncrementTable(name, value)
            else:
                if enc[i] != 0:
                    name, _ = self.GetHeader( enc[i] )
                    i+=1
                    valLen = enc[i]
                    i+=1
                    value = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value
                else:
                    i+=1
                    nameLen = enc[i]
                    i+=1
                    name    = enc[i:i+nameLen].decode()
                    i+=nameLen
                    valLen  = enc[i]
                    i+=1
                    value   = enc[i:i+valLen].decode()
                    i+=valLen
                    Headers[name] = value

        return Headers

class HTTP2_Frame:
    def __init__(self, raw: bytes|None = None, h2type: H2FrameType = H2FrameType.DATA, flags: list[H2Flag]|int = [], streamID: int = 0) -> None:
        if raw != None:
            self.Length   = int.from_bytes(raw[:3])
            self.Type     = H2FrameType(raw[3])
            self.Flags    = self.ParseFlags(raw[4])
            self.StreamID = int.from_bytes(raw[5:9])
            if H2Flag.PADDED in self.Flags:
                self.Paddding = raw[9]
                self.Payload = raw[10:-self.Paddding]
            else:
                self.Paddding = 0
                self.Payload  = raw[9:]
        else:
            self.Length   = 0
            self.Type     = h2type
            self.Flags    = flags if type(flags) == list else self.ParseFlags(flags)
            self.StreamID = streamID
            self.Padding  = 0
            self.Payload  = b''

    def CalculateLength(self) -> None:
        self.Length = len(self.Payload)
        if H2Flag.PADDED in self.Flags:
            self.Length+=1

    def IsFinished(self) -> bool:
        if len(self.Payload) == self.Length:
            return True
        elif len(self.Payload) < self.Length:
            return False
        else:
            raise OverflowError("Payload length is larger then Length assigned in Header")

    def Finish(self, raw: bytes) -> bool:
        self.Payload += raw
        return self.IsFinished()

    def ParseFlags(self, flagsRaw: int) -> list[H2Flag]:
        flags = []
        for flag in H2Flag:
            if flagsRaw & flag.value != 0:
                flags.append(flag)
        if H2Flag(1) in flags and self.Type not in [H2FrameType.HEADERS, H2FrameType.DATA, H2FrameType.CONTINUATION, H2FrameType.SETTINGS, H2FrameType.PING]:
            raise ValueError(f"Unexpected ACK or END_STREAM flag for Frame type {self.Type}")
        elif H2Flag.END_HEADERS in flags and self.Type not in [H2FrameType.HEADERS, H2FrameType.CONTINUATION]:
            raise ValueError(f"Unexpected END_HEADERS flag for Frame type {self.Type}")
        elif H2Flag.PADDED in flags and self.Type not in [H2FrameType.DATA, H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE]:
            raise ValueError(f"Unexpected PADDED flag for Frame type {self.Type}")
        return flags

if __name__ == "__main__":
    hpack = HPACK()
    Headers = b"\x82\x84\x41\x0elocalhost:3000\x86"
    print(Headers)
    Headers = hpack.Decode(Headers)
    print(Headers)
    print(hpack.Encode(Headers))
