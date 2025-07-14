import socket, os
from enum import Enum, Flag, auto
from typing import Any
from hpack import HPACK, CompressionError
from datetime import datetime, timezone
from http_class import HTTP, DATEFORMAT, CODES, Etags

class H2FrameType(Enum):
    DATA            = 0x00
    HEADERS         = 0x01
    RST_STREAM      = 0x03
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

class H2Flag(Flag):
    END_STREAM  = 0b00000001
    END_HEADERS = 0b00000100
    PADDED      = 0b00001000
    ACK         = 0b10000000

class H2StreamState(Enum):
    IDLE               = auto()
    RESERVED_LOCAL     = auto()
    RESERVED_REMOTE    = auto()
    OPEN               = auto()
    HALF_CLOSED_LOCAL  = auto()
    HALF_CLOSED_REMOTE = auto()
    CLOSED             = auto()

class H2FrameNotFinished(Exception):
    def __init__(self, message: str = "Unable to get unfinished Frame Raw") -> None:
        self.message = message
        super().__init__(message)

class H2UnexpectedFlag(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

class H2ConnectionError(Exception):
    def __init__(self, code: H2ErrorCode) -> None:
        message = f"{hex(code.value)} {code.name}"
        self.message = message
        super().__init__(message)

class H2StreamError(Exception):
    def __init__(self, code: H2ErrorCode) -> None:
        message = f"{hex(code.value)} {code.name}"
        self.message = message
        super().__init__(message)

class HTTP2_Frame:
    def __init__(self, raw: bytes|None = None, h2type: H2FrameType = H2FrameType.DATA, flags: H2Flag|int = 0, streamID: int = 0, payload: bytes = b'', padding: int = 0) -> None:
        if raw != None:
            self.Length   = int.from_bytes(raw[:3])
            self.Type     = H2FrameType(raw[3])
            self.Flags    = self.ParseFlags(raw[4])
            self.StreamID = int.from_bytes(raw[5:9])
            if H2Flag.PADDED in self.Flags:
                self.Padding = raw[9]
                self.Payload = raw[10:-self.Padding]
            else:
                self.Padding = 0
                self.Payload  = raw[9:]
        else:
            self.Length   = 0
            self.Type     = h2type
            self.Flags    = flags if type(flags) == H2Flag else self.ParseFlags(flags)
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

    def ParseFlags(self, flagsRaw: int) -> H2Flag:
        flags = H2Flag(0)
        for flag in H2Flag:
            if flagsRaw & flag.value != 0:
                flags = flags | flag
        if H2Flag(1) in flags: 
            if self.Type in [H2FrameType.SETTINGS, H2FrameType.PING]:
                flags = flags ^ ( H2Flag.END_STREAM | H2Flag.ACK )
            elif self.Type not in [H2FrameType.HEADERS, H2FrameType.DATA, H2FrameType.CONTINUATION]:
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

    @staticmethod
    def FormatHeaders(headers: dict[str,str]) -> list[str]:
        raw_lines = []
        mlen = len( max(headers.keys(), key=len) )
        for name, value in headers.items():
            if name == ":status":
                raw_lines.append(f"{name: <{mlen}} = {value} ({CODES[int(value)]})")
            else:
                raw_lines.append(f"{name: <{mlen}} = {value}")
        return raw_lines
        

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
                    raw_lines += self.FormatHeaders(headers)
                case H2FrameType.RST_STREAM:
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
                    raw_lines += self.FormatHeaders(headers)
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
            if H2Flag.PADDED in self.Flags:
                frame.append(self.Padding.to_bytes(1))
            frame.append(self.Payload)
            frame.append(bytes(self.Padding))

            return b''.join(frame)
    def __str__(self) -> str:
        return self.RawFormat()

class HTTP2_Stream:
    def __init__(self, streamID: int, state: H2StreamState = H2StreamState.IDLE, hpack: HPACK = HPACK()) -> None:
        self.StreamID:               int = streamID
        self.AwaitingHeaders:       bool = False
        self.State:        H2StreamState = state
        self.Frames:                list = []
        self.Hpack:                HPACK = hpack

    def Receive(self, frame: HTTP2_Frame) -> Any:
        if frame.StreamID != self.StreamID:
            raise ValueError(f"Received frame belongs to Stream of ID: {frame.StreamID}, not to Stream of ID: {self.StreamID}")
        self.Frames.append(frame)
        if self.AwaitingHeaders:
            if frame.Type == H2FrameType.CONTINUATION:
                return self.ProcessHeaders(frame)
            else:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
        else:
            match self.State:
                case H2StreamState.IDLE:
                    if frame.Type == H2FrameType.HEADERS:
                        if H2Flag.END_STREAM in frame.Flags:
                            self.State = H2StreamState.HALF_CLOSED_REMOTE
                        else:
                            self.State = H2StreamState.OPEN
                        return self.ProcessHeaders(frame)
                    else:
                        raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
                case H2StreamState.RESERVED_LOCAL:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case H2FrameType.WINDOW_UPDATE:
                            return int.from_bytes(frame.Payload)
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
                case H2StreamState.RESERVED_REMOTE:
                    match frame.Type:
                        case H2FrameType.HEADERS:
                            return self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
                case H2StreamState.OPEN:
                    if H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_REMOTE
                    return frame
                case H2StreamState.HALF_CLOSED_LOCAL:
                    if frame.Type == H2FrameType.RST_STREAM or H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.CLOSED
                    else:
                        ''
                case H2StreamState.HALF_CLOSED_REMOTE:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2StreamError(H2ErrorCode.STREAM_CLOSED)
                case H2StreamState.CLOSED:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            return int.from_bytes(frame.Payload)
                        case H2FrameType.PUSH_PROMISE:
                            return self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            ''
                        case _:
                            raise H2ConnectionError(H2ErrorCode.STREAM_CLOSED)

    def ProcessHeaders(self, fheaders: HTTP2_Frame) -> tuple:
        if fheaders.Type not in [H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE, H2FrameType.CONTINUATION]:
            raise ValueError(f"Headers type must be HEADERS, PUSH_PROMISE or CONTINUATION, but not {fheaders.Type.name}")
        if fheaders.Type in [H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE] and H2Flag.END_HEADERS not in fheaders.Flags:
                self.AwaitingHeaders = True
        else:
            if H2Flag.END_HEADERS in fheaders.Flags:
                self.AwaitingHeaders = False

        headers = self.Hpack.DecodeHeaders(fheaders.Payload)
        pseudo  = {}
        for key, val in headers.items():
            if key[0] == ':':
                pseudo[key] = val
                del headers[key]
            else:
                break
        for key in headers.keys():
            if key[0] == ':':
                raise H2StreamError(H2ErrorCode.PROTOCOL_ERROR)
        
        return (pseudo, headers)


    # def Send(self, frame: HTTP2_Frame) -> None:
    #     match self.State:
            
                
if __name__ == "__main__":
    stream = HTTP2_Stream(1)
    while True:
        f = HTTP2_Frame(eval(f"b'{input()}'"))
        print(f.Raw())
        print(stream.Receive(f))
        print(stream.State.name)
