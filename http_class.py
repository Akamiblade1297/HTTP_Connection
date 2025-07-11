from enum import Enum
from pathlib import Path
import os
import hashlib
from posix import urandom
from hpack import HPACK, CompressionError
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

class H2FrameNotFinished(Exception):
    def __init__(self, message: str = "Unable to get unfinished Frame Raw") -> None:
        self.message = message
        super().__init__(message)

class H2UnexpectedFlag(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

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
    END_HEADERS = 0b00000100
    PADDED      = 0b00001000
    ACK         = 0b10000000

class HTTP2_Frame:
    def __init__(self, raw: bytes|None = None, h2type: H2FrameType = H2FrameType.DATA, flags: list[H2Flag]|int = [], streamID: int = 0, payload: bytes = b'', padding: int = 0) -> None:
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
            self.Padding  = padding
            self.Payload  = payload
            self.CalculateLength()

    def CalculateLength(self) -> None:
        self.Length = len(self.Payload)
        if H2Flag.PADDED in self.Flags:
            self.Length+=1

    def IsFinished(self) -> bool:
        if len(self.Payload) + int(H2Flag.PADDED in self.Flags) == self.Length:
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
        if H2Flag(1) in flags: 
            if self.Type in [H2FrameType.HEADERS, H2FrameType.DATA, H2FrameType.CONTINUATION]:
                flags[flags.index(H2Flag(1))] = H2Flag.END_STREAM
            elif self.Type in [H2FrameType.SETTINGS, H2FrameType.PING]:
                flags[flags.index(H2Flag(1))] = H2Flag.ACK
            else:
                raise H2UnexpectedFlag(f"Unexpected ACK or END_STREAM flag for Frame type {self.Type}")
        elif H2Flag.END_HEADERS in flags and self.Type not in [H2FrameType.HEADERS, H2FrameType.CONTINUATION, H2FrameType.PUSH_PROMISE]:
            raise H2UnexpectedFlag(f"Unexpected END_HEADERS flag for Frame type {self.Type}")
        elif H2Flag.PADDED in flags and self.Type not in [H2FrameType.DATA, H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE]:
            raise H2UnexpectedFlag(f"Unexpected PADDED flag for Frame type {self.Type}")
        return flags
    
    def RawFlags(self) -> int:
        flagsRaw = 0
        for flag in self.Flags:
            flagsRaw += flag.value if flag != H2Flag.ACK else 1
        return flagsRaw

    def RawFormat(self, hpack: HPACK = HPACK()) -> str:
        if not self.IsFinished():
            raise H2FrameNotFinished()
        else:
            raw_lines = [ f"{self.Type.name}/{self.StreamID}" ]
            for flag in self.Flags:
                raw_lines.append(f"+ {flag.name}")
            
            match self.Type:
                case H2FrameType.DATA:
                    raw_lines.append(f"[{self.Length} Bytes of data]")
                case H2FrameType.HEADERS | H2FrameType.CONTINUATION:
                    headers = hpack.DecodeHeaders(self.Payload)
                    for name, value in headers.items():
                        raw_lines.append(f"{name} = {value}")
                case H2FrameType.RST_STEAM:
                    raw_lines.append(H2ErrorCode(int.from_bytes(self.Payload)).name)
                case H2FrameType.SETTINGS:
                    i,j = 0,2
                    while j < len(self.Payload):
                        name = H2Settings(int.from_bytes(self.Payload[i:j]))
                        i  = j
                        j += 4
                        value = int.from_bytes(self.Payload[i:j])
                        raw_lines.append(f"{name} = {value}")
                        i  = j
                        j += 2
                case H2FrameType.PUSH_PROMISE:
                    raw_lines.append(f"Promised-Stream-ID = {int.from_bytes(self.Payload[:4])}")
                    headers = hpack.DecodeHeaders(self.Payload[4:])
                    for name, value in headers.items():
                        raw_lines.append(f"{name} = {value}")
                case H2FrameType.PING:
                    raw_lines.append(''.join([ hex(v)[2:] + ' ' if (i+1)%2 == 0 else hex(v)[2:] for i,v in enumerate(self.Payload) ]))
                case H2FrameType.GOAWAY:
                    raw_lines.append(f"Last-Stream-ID = {int.from_bytes(self.Payload[:4])}")
                    error = int.from_bytes(self.Payload[4:8])
                    raw_lines.append(f"Error Code = {hex(error)} {H2ErrorCode(error).name}")
                    try:
                        raw_lines.append(self.Payload[8:].decode())
                    except: ''
                case H2FrameType.WINDOW_UPDATE:
                    raw_lines.append(f"Window Size Increment = {int.from_bytes(self.Payload)}")
            
            return '\n    '.join(raw_lines)

    def Raw(self) -> bytes:
        if not self.IsFinished():
            raise H2FrameNotFinished()
        else:
            frame = []
            frame.append(self.Length.to_bytes(3))
            frame.append(self.Type.value.to_bytes(1))
            frame.append(self.RawFlags().to_bytes(1))
            frame.append(self.StreamID.to_bytes(4))
            if self.Padding != 0:
                frame.append(self.Padding.to_bytes(1))
            frame.append(self.Payload)
            frame.append(bytes(self.Padding))

            return b''.join(frame)
    def __str__(self) -> str:
        return self.RawFormat()

if __name__ == "__main__":
    sframeS_1 = HTTP2_Frame(
        h2type  = H2FrameType.SETTINGS,
        flags   = 0b00000000,
        payload = b'\x00\x03\x00\x00\x00\x64',
    )
    cframeS_1 = HTTP2_Frame(
        h2type  = H2FrameType.SETTINGS,
        flags   = 0b00000000,
        payload = b'\x00\x02\x00\x00\x00\x01\x00\x09\x00\x00\x00\x01',
    )
    sframeS_2 = HTTP2_Frame(
        h2type  = H2FrameType.SETTINGS,
        flags   = 0b00000001
    )
    cframeS_2 = HTTP2_Frame(
        h2type  = H2FrameType.SETTINGS,
        flags   = 0b00000001
    )
    
    cframe1_1 = HTTP2_Frame(
        h2type  = H2FrameType.HEADERS,
        streamID= 1,
        flags   = 0b00000101,
        payload = b'\x82\x86\x84\x41\x0bexample.com\x53\x09text/html\x54\x02ru\x7a\x0eMy-Browser/1.0'
    )
    sframe1_1 = HTTP2_Frame(
        h2type  = H2FrameType.PUSH_PROMISE,
        streamID= 1,
        flags   = 0b00000100,
        payload = b'\x00\x00\x00\x02\x82\x44\x0a/style.css\x86'
    )
    sframe1_2 = HTTP2_Frame(
        h2type  = H2FrameType.HEADERS,
        streamID= 1,
        flags   = 0b00000100,
        payload = b'\x88\x5f\x09text/html'
    )
    sframe1_3 = HTTP2_Frame(
        h2type  = H2FrameType.DATA,
        streamID= 1,
        flags   = 0b00000001,
        payload = os.urandom(2048)
    )

    sframe2_1 = HTTP2_Frame(
        h2type  = H2FrameType.HEADERS,
        streamID= 2,
        flags   = 0b00000100,
        payload = b'\x88\x5f\x09style/css'
    )
    sframe2_2 = HTTP2_Frame(
        h2type  = H2FrameType.DATA,
        streamID= 2,
        flags   = 0b00001001,
        padding = 8,
        payload = os.urandom(256)
    )

    ping = os.urandom(8)
    cframeP_1 = HTTP2_Frame(
        h2type  = H2FrameType.PING,
        flags   = 0b00000000,
        payload = ping
    )
    sframeP_1 = HTTP2_Frame(
        h2type  = H2FrameType.PING,
        flags   = 0b00000001,
        payload = ping
    )

    cframeG = HTTP2_Frame(
        h2type  = H2FrameType.GOAWAY,
        payload = b'\x00\x00\x00\x00'
    )

    print('-'*20)
    print('-'*20)
    print(sframeS_1)
    print('-'*20)
    print(cframeS_1)
    print('-'*20)
    print(sframeS_2)
    print('-'*20)
    print(cframeS_2)
    print('-'*20)
    print()
    print('-'*20)
    print(cframe1_1)
    print('-'*20)
    print(sframe1_1)
    print(sframe1_2)
    print(sframe1_3)
    print('-'*20)
    print()
    print('-'*20)
    print(sframe2_1)
    print(sframe2_2)
    print('-'*20)
    print()
    print('-'*20)
    print(cframeP_1)
    print('-'*20)
    print(sframeP_1)
    print('-'*20)
    print()
    print('-'*20)
    print(cframeG)
    print('-'*20)
    print('-'*20)
