import socket, os
import threading
from enum import Enum, Flag, auto
from typing import Any, Callable
from hpack import HPACK, CompressionError
from datetime import datetime, timezone
from http import HTTP, DATEFORMAT, CODES, Etags

PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

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

class H2Setting(Enum):
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

DEFAULT_SETTINGS = {
    H2Setting.HEADER_TABLE_SIZE.               value: 4096  ,
    H2Setting.ENABLE_PUSH.                     value: 1     ,
    H2Setting.MAX_CONCURENT_STREAMS.           value: -1    ,
    H2Setting.INITIAL_WINDOW_SIZE.             value: 65535 ,
    H2Setting.MAX_FRAME_SIZE.                  value: 16384 ,        
    H2Setting.MAX_HEADER_LIST_SIZE.            value: -1    ,
    H2Setting.SETTINGS_ENABLE_CONNECT_PROTOCOL.value: 0     ,
    H2Setting.SETTINGS_NO_RFC7540_PRIORITIES.  value: 0     ,
    H2Setting.TLS_RENEG_PERMITTED.             value: 0x00  ,
    H2Setting.SETTINGS_ENABLE_METADATA.        value: 0     ,
}

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

class H2InternalError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

class H2ConnectionError(Exception):
    def __init__(self, code: H2ErrorCode, DebugInfo: str = '') -> None:
        message = f"{hex(code.value)} {code.name} {DebugInfo}"
        self.Code = code.value
        self.message = message
        super().__init__(message)

class H2StreamError(Exception):
    def __init__(self, code: H2ErrorCode, DebugInfo: str = '') -> None:
        message = f"{hex(code.value)} {code.name} {DebugInfo}"
        self.Code = code.value
        self.message = message
        super().__init__(message)

class HTTP2_Frame:
    def __init__(self, raw: bytes|None = None, h2type: H2FrameType = H2FrameType.DATA, flags: H2Flag|int = H2Flag(0), streamID: int = 0, payload: bytes = b'', padding: int = 0) -> None:
        if raw != None:
            self.Length   = int.from_bytes(raw[:3])
            self.Type     = H2FrameType(raw[3])
            self.Flags    = self.ParseFlags(raw[4], self.Type)
            self.StreamID = int.from_bytes(raw[5:9]) & ~(1<<31)
            if H2Flag.PADDED in self.Flags:
                self.Padding = raw[9]
                self.Payload = raw[10:-self.Padding]
            else:
                self.Padding = 0
                self.Payload  = raw[9:]
            if self.StreamID > (2**31-1): raise H2InternalError("StreamID is too large.")
        else:
            self.Length   = 0
            self.Type     = h2type
            self.Flags    = flags if type(flags) == H2Flag else self.ParseFlags(flags, self.Type)
            self.StreamID = streamID
            self.Padding  = padding
            self.Payload  = payload
            self.CalculateLength()

    def CalculateLength(self) -> None:
        self.Length = len(self.Payload) + ( self.Padding + 1 if H2Flag.PADDED in self.Flags else 0)

    @staticmethod
    def ParseFlags(flagsRaw: int, h2type: H2FrameType) -> H2Flag:
        flags = H2Flag(0)
        for flag in H2Flag:
            if flagsRaw & flag.value != 0:
                flags = flags | flag
        if H2Flag(1) in flags: 
            if h2type in [H2FrameType.SETTINGS, H2FrameType.PING]:
                flags = flags ^ ( H2Flag.END_STREAM | H2Flag.ACK )
            elif h2type not in [H2FrameType.HEADERS, H2FrameType.DATA, H2FrameType.CONTINUATION]:
                raise H2InternalError(f"Unexpected ACK or END_STREAM Flag for {h2type} Frame")
        elif H2Flag.END_HEADERS in flags and h2type not in [H2FrameType.HEADERS, H2FrameType.CONTINUATION, H2FrameType.PUSH_PROMISE]:
            raise H2InternalError(f"Unexpected END_HEADERS Flag for {h2type} Frame")
        elif H2Flag.PADDED in flags and h2type not in [H2FrameType.DATA, H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE]:
            raise H2InternalError(f"Unexpected PADDED Flag for {h2type} Frame")
        return flags
    
    def RawFlags(self) -> int:
        flagsRaw = 0
        for flag in self.Flags:
            flagsRaw += flag.value if flag != H2Flag.ACK else 1
        return flagsRaw

    @staticmethod
    def ParseRaw(raw: bytes) -> tuple[list,bytes]:
        frames = []
        i = 0
        while i < len(raw):
            try:
                length = int.from_bytes(raw[i:i+3])
                frame_full_size = 9+length
                frames.append(HTTP2_Frame(raw[i:i+frame_full_size]))
                i += frame_full_size
            except IndexError:
                break
        return (frames, raw[i:])

    def ParsePayload(self, hpack: HPACK = HPACK()) -> Any:
        match self.Type:
            case H2FrameType.DATA | H2FrameType.PING:
                return self.Payload
            case H2FrameType.HEADERS| H2FrameType.CONTINUATION:
                headers = hpack.DecodeHeaders(self.Payload)
                return headers
            case H2FrameType.PUSH_PROMISE:
                promissed_stream = int.from_bytes(self.Payload[:4])
                headers          = hpack.DecodeHeaders(self.Payload[4:])
                return (headers, promissed_stream)
            case H2FrameType.RST_STREAM:
                error = H2ErrorCode(int.from_bytes(self.Payload))
                return error
            case H2FrameType.GOAWAY:
                last_stream = int.from_bytes(self.Payload[:4])
                error       = H2ErrorCode(self.Payload[4:8])
                try:    debug_info = self.Payload[8:]
                except: debug_info = ''
                return ( last_stream, error, debug_info ) 
            case H2FrameType.SETTINGS:
                settings = []
                i,j = 0,2
                while j < len(self.Payload):
                    name = int.from_bytes(self.Payload[i:j])
                    i  = j
                    j += 4
                    value = int.from_bytes(self.Payload[i:j])
                    i  = j
                    j += 2
                    settings.append((name,value))
                return settings
            case H2FrameType.WINDOW_UPDATE:
                increment = int.from_bytes(self.Payload)
                return increment

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
        
    def Raw(self) -> bytes:
        frame = []
        frame.append(self.Length.to_bytes(3))
        frame.append(self.Type.value.to_bytes(1))
        frame.append(self.RawFlags().to_bytes(1))
        frame.append(self.StreamID.to_bytes(4))
        if H2Flag.PADDED in self.Flags:
            frame.append(self.Padding.to_bytes(1))
        frame.append(self.Payload)
        if H2Flag.PADDED in self.Flags:
            frame.append(bytes(self.Padding))

        return b''.join(frame)
    
    def RawDump(self) -> str:
        raw = self.Raw()
        dump_lines = []

        for j in range(0,len(raw),8):
            hx,txt = [],[]
            for i in range(8):
                if j+i >= len(raw): break
                b = raw[j+i]
                hx.append(f"{b:02X}")
                if i == 3:
                    hx.append('')
                txt.append( chr(b) if b>=32 and b<=126 else '\033[2m·\033[0m' )
            dump_lines.append(f"{' '.join(hx): <24} | {' '.join(txt)} ")

        return '\n'.join(dump_lines)

    def RawFormat(self, prefix: str = '', hpack: HPACK = HPACK()) -> str:
        parsed = self.ParsePayload(hpack)
        raw_lines = [ f"{prefix}{self.Type.name}/{self.StreamID}" ]
        for flag in self.Flags:
            raw_lines.append(f"+ {flag.name}")
        
        match self.Type:
            case H2FrameType.DATA:
                raw_lines.append(f"[{self.Length} Bytes of data]")
            case H2FrameType.HEADERS | H2FrameType.CONTINUATION:
                raw_lines += self.FormatHeaders(parsed)
            case H2FrameType.RST_STREAM:
                raw_lines.append(f"{parsed.value} {parsed.name}")
            case H2FrameType.SETTINGS:
                for name, value in parsed:
                    raw_lines.append(f"{H2Setting(name).name} = {value}")
            case H2FrameType.PUSH_PROMISE:
                raw_lines.append(f"Promised-Stream-ID = {parsed[0]}")
                raw_lines += self.FormatHeaders(parsed[1])
            case H2FrameType.PING:
                raw_lines.append(''.join([ hex(v)[2:] + ' ' if (i+1)%2 == 0 else hex(v)[2:] for i,v in enumerate(parsed) ]))
            case H2FrameType.GOAWAY:
                raw_lines.append(f"Last-Stream-ID = {int.from_bytes(parsed[0])}")
                raw_lines.append(f"Error Code = {hex(parsed[1].value)} {parsed[1].name}")
                raw_lines.append(parsed[2])
            case H2FrameType.WINDOW_UPDATE:
                raw_lines.append(f"Window Size Increment = {parsed[0]}")
        
        return ('\n    ' + prefix).join(raw_lines)

    def __eq__(self, other) -> bool:
        if type(other) != HTTP2_Frame:
            raise TypeError(f"Can't compare HTTP2_Frame to {type(other)}")
        return (other.Raw() == self.Raw())

ACK = HTTP2_Frame(h2type=H2FrameType.SETTINGS,
    flags = 1
)

class HTTP2_Stream:
    def __init__(self, streamID: int, state: H2StreamState = H2StreamState.IDLE, hpack: HPACK = HPACK()) -> None:
        self.StreamID:               int = streamID
        self.AwaitingHeaders:       bool = False
        self.State:        H2StreamState = state
        self.Hpack:                HPACK = hpack

    def Receive(self, frame: HTTP2_Frame) -> Any:
        if frame.StreamID != self.StreamID:
            raise ValueError(f"Received frame belongs to Stream of ID: {frame.StreamID}, not to Stream of ID: {self.StreamID}")
        if frame.Padding >= frame.Length:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
        elif self.AwaitingHeaders:
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
                            return frame
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
                case H2StreamState.RESERVED_REMOTE:
                    match frame.Type:
                        case H2FrameType.HEADERS:
                            self.State = H2StreamState.CLOSED if H2Flag.END_STREAM in frame.Flags else H2StreamState.HALF_CLOSED_LOCAL
                            return self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR)
                case H2StreamState.OPEN:
                    if frame.Type == H2FrameType.RST_STREAM:
                        self.State = H2StreamState.CLOSED
                    elif H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_REMOTE
                    return frame
                case H2StreamState.HALF_CLOSED_LOCAL:
                    if frame.Type == H2FrameType.RST_STREAM or H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.CLOSED
                    else:
                        return frame
                case H2StreamState.HALF_CLOSED_REMOTE:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2StreamError(H2ErrorCode.STREAM_CLOSED)
                case H2StreamState.CLOSED:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            return frame
                        case H2FrameType.PUSH_PROMISE:
                            return self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            ''
                        case _:
                            raise H2ConnectionError(H2ErrorCode.STREAM_CLOSED)

    def Send(self, frame: HTTP2_Frame) -> None:
        if frame.StreamID != self.StreamID:
            raise H2InternalError(f"Sent frame belongs to Stream of ID: {frame.StreamID}, not to Stream of ID: {self.StreamID}")
        elif self.AwaitingHeaders == True:
            if frame.Type != H2FrameType.CONTINUATION:
                raise H2InternalError(f"CONTINUATION Frame expected, got {frame.Type.name}")
            else:
                self.ProcessHeaders(frame)
                return
        else:
            match self.State:
                case H2StreamState.IDLE:
                    if frame.Type != H2FrameType.HEADERS:
                        raise H2InternalError(f"HEADERS Frame expected on IDLE Stream, got {frame.Type.name}")
                    else:
                        self.ProcessHeaders(frame)
                        if H2Flag.END_STREAM in frame.Flags:
                            self.State = H2StreamState.HALF_CLOSED_LOCAL
                        else:
                            self.State = H2StreamState.OPEN
                case H2StreamState.RESERVED_LOCAL:
                    match frame.Type:
                        case H2FrameType.HEADERS:
                            self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            ''
                        case _:
                            raise H2InternalError(f"HEADERS or RST_STREAM Frame expected on RESERVED(LOCAL) Stream, got {frame.Type.name}")
                case H2StreamState.RESERVED_REMOTE:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            ''
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2InternalError(f"WINDOW_UPDATE or RST_STREAM Frame expected on RESERVERD(REMOTE) Stream, got {frame.Type.name}")
                case H2StreamState.OPEN:
                    if frame.Type == H2FrameType.RST_STREAM:
                        self.State = H2StreamState.CLOSED
                    elif H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_LOCAL
                case H2StreamState.HALF_CLOSED_LOCAL:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case H2FrameType.WINDOW_UPDATE:
                            ''
                        case _:
                            raise H2InternalError(f"WINDOW_UPDATE or RST_STREAM Frame expected on HALF_CLOSED(LOCAL) Stream, got {frame.Type.name}")
                case H2StreamState.HALF_CLOSED_REMOTE:
                    if frame.Type == H2FrameType.RST_STREAM or H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.CLOSED
                case H2StreamState.CLOSED:
                    raise H2InternalError("Can't send any Frames on CLOSED Stream")
                    

    def ProcessHeaders(self, fheaders: HTTP2_Frame) -> tuple:
        if fheaders.Type not in [H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE, H2FrameType.CONTINUATION]:
            raise H2InternalError(f"Headers type must be HEADERS, PUSH_PROMISE or CONTINUATION, but not {fheaders.Type.name}")
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
            else:
                break
        for key in pseudo.keys():
            del headers[key]
        for key in headers.keys():
            if key[0] == ':':
                raise H2StreamError(H2ErrorCode.PROTOCOL_ERROR)
        
        return (pseudo, headers)

class HTTP2_Connection:
    def __init__(self, conn: socket.socket, server: bool = True):
        self.Settings   :dict[int,int]     = {}
        self.Queued     :list[HTTP2_Frame] = []
        self.Hpack      :HPACK             = HPACK()
        self.Server     :bool              = server
        self.Connection :socket.socket     = conn
        
        self.SetSetting(H2Setting.SETTINGS_NO_RFC7540_PRIORITIES, 1)

    def GetSetting(self, setting: H2Setting) -> int:
        if setting.value in self.Settings:
            return self.Settings[setting.value]
        else:
            return DEFAULT_SETTINGS[setting.value]

    def SetSetting(self, setting: H2Setting, value: int) -> None:
        self.Settings[setting.value] = value

    def SettingsRaw(self) -> bytes:
        return b''.join([ code.to_bytes(2) + value.to_bytes(4) if value != DEFAULT_SETTINGS[code] else b'' for code, value in self.Settings.items() ])

    def ParseHeadersFromString(self, request_str: str) -> bytes:
        headers_values = request_str.split(';')
        headers = {}
        for header in headers_values:
            try:
                name, value = header.split('=')
                headers[name] = value
            except:
                continue
        return self.Hpack.EncodeHeaders(headers)

    def Queue(self, frames: HTTP2_Frame|list[HTTP2_Frame]) -> None:
        if type(frames) == list:
            self.Queued += frames
        elif type(frames) == HTTP2_Frame:
            self.Queued.append(frames)

    def Preface(self, request_str: str = ":method=GET;:path=/;:scheme=http;:authority=localhost:3000") -> None:
        if self.Server:
            preamble = self.Connection.recv(24)
            if preamble != PREAMBLE:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Invalid Client Preface")
            frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(65535))
            settings = frames[0]
            if settings.Type == H2FrameType.SETTINGS:
                for name, value in settings.ParsePayload():
                    self.Settings[name] = value
            else:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Invalid Client Preface")
            self.Queue(frames[1:])
            
            settings = HTTP2_Frame (h2type=H2FrameType.SETTINGS,
                payload = self.SettingsRaw()
            )
            self.Connection.send(settings.Raw() + ACK.Raw())

            try:
                frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(10))
                if frames[0] != ACK:
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "No ACK Frame received")
            except TimeoutError:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "No ACK Frame received")
            print("Connection Established.\n\nQueue:")
            print('\n\n'.join([frame.RawFormat(hpack=self.Hpack) for frame in self.Queued]))
        else:
            settings = HTTP2_Frame (h2type=H2FrameType.SETTINGS,
                payload = self.SettingsRaw()
            )
            request = HTTP2_Frame (h2type=H2FrameType.HEADERS,
                payload = self.ParseHeadersFromString(request_str),
                flags   = H2Flag.END_HEADERS | H2Flag.END_STREAM,
                streamID= 1
            )
            
            self.Connection.send(PREAMBLE + settings.Raw() + request.Raw())
            
            frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(65535))
            if len(frames) == 1:
                if not ( frames[0].Type == H2FrameType.SETTINGS and frames[0].RawFlags() == 0):
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Invalid Server Preface")
                for name, value in frames[0].ParsePayload():
                    self.Settings[name] = value
                self.Connection.send(ACK.Raw())

                frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(65535))
                if frames[0] != ACK:
                    raise H2InternalError("No ACK Frame received")
            elif len(frames) == 2:
                if not ( frames[0].Type == H2FrameType.SETTINGS and frames[0].RawFlags() == 0 and frames[1] == ACK ):
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Invalid Server Preface")
                for name, value in frames[0].ParsePayload():
                    self.Settings[name] = value
                self.Connection.send(ACK.Raw())

if __name__ == "__main__":
    hpack = HPACK()
    server = socket.socket()
    server.bind(('localhost',3000))
    server.listen()
    conn, _ = server.accept()
    conn.settimeout(5)
    Connection = HTTP2_Connection(conn)

    Connection.Preface()

 #
 #    while True:
 #        b = eval(f"b'{input()}'")
 #        f = HTTP2_Frame(b[1:])
 #        if b[0] == 0:
 #            print(f.RawFormat(hpack=stream.Hpack))
 #            stream.Receive(f)
 #        elif b[0] == 1:
 #            print(f.RawFormat('    ',hpack=stream.Hpack))
 #            stream.Send(f)
 #        print(stream.State.name)
