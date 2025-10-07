import socket, os
import multiprocessing as mp
from enum import Enum, Flag, auto
from typing import Any, Callable
from hpack import HPACK, CompressionError
from datetime import datetime, timezone
import time
from http import HTTP, DATEFORMAT, CODES, Etags

def Dump(raw: bytes, ascii: bool = True) -> str:
    dump_lines = []

    for j in range(0,len(raw),8):
        hx,txt = [],[]
        for i in range(8):
            if j+i >= len(raw): break
            b = raw[j+i]
            hx.append(f"{b:02X}")
            if i == 3:
                hx.append('')
            if ascii: txt.append( chr(b) if b>=32 and b<=126 else '\033[2m·\033[0m' )
        dump_lines.append(f"{' '.join(hx): <24}" + (" | {' '.join(txt)} " if ascii else ''))

    return '\n'.join(dump_lines)

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
    HEADER_TABLE_SIZE                = 0x02
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
        self.Code = code
        self.message = message
        super().__init__(message)

class H2StreamError(Exception):
    def __init__(self, code: H2ErrorCode, streamID: int) -> None:
        message = f"{hex(code.value)} {code.name}"
        self.StreamID = streamID
        self.Code = code
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
            if self.StreamID > (2**31-1):
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "StreamID is too large.")
        else:
            self.Length   = 0
            self.Type     = h2type
            self.Flags    = flags if type(flags) == H2Flag else self.ParseFlags(flags, self.Type)
            self.StreamID = streamID
            self.Padding  = padding
            self.Payload  = payload
            self.CalculateLength()
            if self.StreamID > (2**31-1):
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR,"StreamID must NOT be larger then 2^31-1.")
            length = self.Length
            self.CalculateLength()
            if self.Length != length:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR,"Specified Length differs from an actual Payload length")

        match self.Type:
            case H2FrameType.DATA | H2FrameType.HEADERS | H2FrameType.CONTINUATION | H2FrameType.PUSH_PROMISE | H2FrameType.RST_STREAM:
                if self.StreamID == 0:
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, f"{self.Type} Frame StreamID must differ from 0 ")
            case H2FrameType.SETTINGS | H2FrameType.PING | H2FrameType.GOAWAY:
                if self.StreamID != 0:
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, f"{self.Type} Frame StreamID must be set to 0")
        match self.Type:
            case H2FrameType.RST_STREAM:
                if self.Length != 4:
                    raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "RST_STREAM Frame Payload must be 4 Octets long")
            case H2FrameType.SETTINGS:
                if H2Flag.ACK in self.Flags and self.Length > 0:
                    raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS Frame Payload with ACK Flag must be empty")
                elif self.Length % 6 != 0:
                    raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS Frame Length must be a multiple of 6")
            case H2FrameType.PING:
                if self.Length != 8:
                    raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "PING Frame Payload must be 8 Octets long")
            case H2FrameType.WINDOW_UPDATE:
                if self.Length != 4:
                    raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "WINDOW_UPDATE Frame Payload must be 4 Octets long")
                elif self.ParsePayload() == 0:
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE Frame Payload must differ from 0")
        if H2Flag.PADDED in self.Flags and self.Padding >= self.Length:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Padding length must NOT be greater or equal then Payload length")

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
                error       = H2ErrorCode(int.from_bytes(self.Payload[4:8]))
                try:    debug_info = self.Payload[8:].decode()
                except: debug_info = self.Payload[8:]
                return ( last_stream, error, debug_info ) 
            case H2FrameType.SETTINGS:
                settings = {}
                i,j = 0,2
                while j < len(self.Payload):
                    name = int.from_bytes(self.Payload[i:j])
                    i  = j
                    j += 4
                    value = int.from_bytes(self.Payload[i:j])
                    i  = j
                    j += 2
                    settings[name] = value
                return settings
            case H2FrameType.WINDOW_UPDATE:
                increment = int.from_bytes(self.Payload)
                return increment
    
    def WritePayload(self, payload: bytes):
        self.Payload = payload
        self.CalculateLength()

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
        return Dump(self.Raw())

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
                for name, value in parsed.items():
                    raw_lines.append(f"{H2Setting(name).name} = {value}")
            case H2FrameType.PUSH_PROMISE:
                raw_lines.append(f"Promised-Stream-ID = {parsed[0]}")
                raw_lines += self.FormatHeaders(parsed[1])
            case H2FrameType.PING:
                raw_lines.append(''.join([ hex(v)[2:] + ' ' if (i+1)%2 == 0 else hex(v)[2:] for i,v in enumerate(parsed) ]))
            case H2FrameType.GOAWAY:
                raw_lines.append(f"Last-Stream-ID = {parsed[0]}")
                raw_lines.append(f"Error Code = {hex(parsed[1].value)} {parsed[1].name}")
                raw_lines.append(parsed[2] if type(parsed[2]) == str else Dump(parsed[2], False))
            case H2FrameType.WINDOW_UPDATE:
                raw_lines.append(f"Window Size Increment = {parsed[0]}")
        
        return ('\n    ' + prefix).join(raw_lines)

    def __eq__(self, other) -> bool:
        if type(other) == HTTP2_Frame:
            return ( other.Raw() == self.Raw() )
        elif type(other) == bytes:
            return ( other == self.Raw() )
        else:
            return False

SETTINGS_ACK = HTTP2_Frame(h2type=H2FrameType.SETTINGS,
    flags = H2Flag.ACK
)

class HTTP2_Stream:
    def __init__(self, streamID: int, state: H2StreamState = H2StreamState.IDLE, init_window: int = 65535) -> None:
        self.WindowSelf:             int = init_window
        self.WindowPeer:             int = init_window
        self.StreamID:               int = streamID
        self.AwaitingHeaders:       bool = False
        self.State:        H2StreamState = state

    def Receive(self, frame: HTTP2_Frame) -> None:
        if frame.StreamID != self.StreamID:
            raise ValueError(f"Received frame belongs to Stream of ID: {frame.StreamID}, not to Stream of ID: {self.StreamID}")
        elif self.AwaitingHeaders:
            if frame.Type != H2FrameType.CONTINUATION:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "CONTINUATION Frame expected")

            self.ProcessHeaders(frame)
        else:
            match self.State:
                case H2StreamState.IDLE:
                    if self.StreamID % 2 == 0:
                        raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Client-initiated streams must have Odd StreamID")
                    elif frame.Type != H2FrameType.HEADERS:
                        raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Idle Streams can't receive any Frames other then HEADERS")

                    if H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_REMOTE
                    else:
                        self.State = H2StreamState.OPEN
                    self.ProcessHeaders(frame)
                case H2StreamState.RESERVED_LOCAL:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case H2FrameType.WINDOW_UPDATE:
                            ""
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Reserved(local) Streams can't receive any Frames other then RST_Stream or WINDOW_UPDATE")
                case H2StreamState.RESERVED_REMOTE:
                    match frame.Type:
                        case H2FrameType.HEADERS:
                            self.State = H2StreamState.CLOSED if H2Flag.END_STREAM in frame.Flags else H2StreamState.HALF_CLOSED_LOCAL
                            self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Reserved(local) Streams can't receive any Frames other then HEADERS or RST_STREAM")
                case H2StreamState.OPEN:
                    if frame.Type == H2FrameType.RST_STREAM:
                        self.State = H2StreamState.CLOSED
                    elif H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_REMOTE
                    return
                case H2StreamState.HALF_CLOSED_LOCAL:
                    if frame.Type == H2FrameType.RST_STREAM or H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.CLOSED
                    else:
                        return
                case H2StreamState.HALF_CLOSED_REMOTE:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2StreamError(H2ErrorCode.STREAM_CLOSED, self.StreamID)
                case H2StreamState.CLOSED:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            ''
                        case H2FrameType.PUSH_PROMISE:
                            self.ProcessHeaders(frame)
                        case H2FrameType.RST_STREAM:
                            ''
                        case _:
                            raise H2ConnectionError(H2ErrorCode.STREAM_CLOSED)
            # FLOW CONTROL
            match frame.Type:
                case H2FrameType.WINDOW_UPDATE:
                    self.WindowPeer += frame.ParsePayload()
                    if self.WindowPeer > 2**31-1:
                        raise H2StreamError(H2ErrorCode.FLOW_CONTROL_ERROR, self.StreamID)
                case H2FrameType.DATA:
                    self.WindowSelf -= frame.Length
                    if self.WindowSelf < 0:
                        raise H2StreamError(H2ErrorCode.FLOW_CONTROL_ERROR, self.StreamID)

    def Send(self, frame: HTTP2_Frame) -> None:
        if frame.StreamID != self.StreamID:
            raise H2InternalError(f"Sent frame belongs to Stream of ID: {frame.StreamID}, not to Stream of ID: {self.StreamID}")
        elif self.AwaitingHeaders == True:
            if frame.Type != H2FrameType.CONTINUATION:
                raise H2InternalError(f"CONTINUATION Frame expected, got {frame.Type.name}")
            else:
                self.ProcessHeaders(frame)
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
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2InternalError(f"HEADERS or RST_STREAM Frame expected on RESERVED(LOCAL) Stream, got {frame.Type.name}")
                case H2StreamState.RESERVED_REMOTE:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            ""
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case _:
                            raise H2InternalError(f"WINDOW_UPDATE or RST_STREAM Frame expected on RESERVERD(REMOTE) Stream, got {frame.Type.name}")
                case H2StreamState.OPEN:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case H2FrameType.DATA:
                            ""
                        case H2FrameType.WINDOW_UPDATE:
                            ""
                    if H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.HALF_CLOSED_LOCAL
                case H2StreamState.HALF_CLOSED_LOCAL:
                    match frame.Type:
                        case H2FrameType.RST_STREAM:
                            self.State = H2StreamState.CLOSED
                        case H2FrameType.WINDOW_UPDATE:
                            ""
                        case _:
                            raise H2InternalError(f"WINDOW_UPDATE or RST_STREAM Frame expected on HALF_CLOSED(LOCAL) Stream, got {frame.Type.name}")
                case H2StreamState.HALF_CLOSED_REMOTE:
                    if frame.Type == H2FrameType.RST_STREAM or H2Flag.END_STREAM in frame.Flags:
                        self.State = H2StreamState.CLOSED
                case H2StreamState.CLOSED:
                    raise H2InternalError(f"Can't send any Frames on CLOSED Stream")
            # FLOW CONTROL
            match frame.Type:
                case H2FrameType.WINDOW_UPDATE:
                    self.WindowPeer += frame.ParsePayload()
                    if self.WindowPeer > 2**31-1:
                        raise H2InternalError("Window size can't exceed 2^31-1")
                case H2FrameType.DATA:
                    self.WindowPeer -= frame.Length
                    if self.WindowPeer < 0:
                        raise H2InternalError("DATA Frame is too Large, Stream Window exceed")
                    

    def ProcessHeaders(self, fheaders: HTTP2_Frame) -> None:
        if fheaders.Type not in [H2FrameType.HEADERS, H2FrameType.PUSH_PROMISE, H2FrameType.CONTINUATION]:
            raise H2InternalError(f"Headers type must be HEADERS, PUSH_PROMISE or CONTINUATION, but not {fheaders.Type.name}")

        if H2Flag.END_HEADERS not in fheaders.Flags:
            self.AwaitingHeaders = True
        else:
            self.AwaitingHeaders = False

class HTTP2_StreamList:
    def __init__(self) -> None:
        self.Streams: set[HTTP2_Stream] = set()

    def __getitem__(self, streamID: int) -> HTTP2_Stream:
        for stream in self.Streams:
            if stream.StreamID == streamID:
                return stream
        stream = HTTP2_Stream(streamID)
        self.Streams.add(stream)
        return stream

    def Reserve(self, streamID: int, server: bool = True) -> None:
        if server:
            self[streamID].State = H2StreamState.RESERVED_LOCAL
        else:
            self[streamID].State = H2StreamState.RESERVED_REMOTE

    def Concurent(self) -> int:
        concurent_streams = 0
        for stream in self.Streams:
            if stream.State in [H2StreamState.OPEN, H2StreamState.HALF_CLOSED_LOCAL, H2StreamState.HALF_CLOSED_REMOTE]:
                concurent_streams+=1
        return concurent_streams

class HTTP2_Connection:
    def __init__(self, conn: socket.socket, server: bool = True, timeout: int = 5, init_conn_window: int = 65535):
        self.Namespace = mp.Manager().Namespace()

        self.Connection              = conn
        self.Namespace.Server        = server
        self.Namespace.Timeout       = timeout

        self.Namespace.Settings      = {}
        self.Namespace.Queued        = []
        self.Namespace.ACKQueued     = []
        self.Namespace.ZeroQueued    = []
        self.Namespace.Hpack         = HPACK()
        self.Namespace.Streams       = HTTP2_StreamList()
        self.Namespace.Last_StreamID = 0
        self.Namespace.WindowSelf    = init_conn_window
        self.Namespace.WindowPeer    = 65535

        if self.Namespace.WindowSelf < 65535:
            raise H2InternalError("Can't set Initial Connection Window size less then 65535")

        self.SetSetting(H2Setting.SETTINGS_NO_RFC7540_PRIORITIES, 1)

    def GetSetting(self, setting: H2Setting) -> int:
        if setting.value in self.Namespace.Settings:
            return self.Namespace.Settings[setting.value]
        else:
            return DEFAULT_SETTINGS[setting.value]

    def SetSetting(self, setting: H2Setting, value: int) -> None:
        self.Namespace.Settings[setting.value] = value

    def SetSettingsTable(self, settings: dict[int,int]) -> None:
        for setting, value in settings.items():
            self.Namespace.Settings[setting] = value

    def SettingsRaw(self) -> bytes:
        return b''.join([ code.to_bytes(2) + value.to_bytes(4) if value != DEFAULT_SETTINGS[code] else b'' for code, value in self.Namespace.Settings.items() ])

    def ParseHeadersFromString(self, request_str: str) -> bytes:
        headers_values = request_str.split(';')
        headers = {}
        for header in headers_values:
            try:
                name, value = header.split('=')
                headers[name] = value
            except:
                continue
        return self.Namespace.Hpack.EncodeHeaders(headers)

    def Queue(self, frames: HTTP2_Frame|list[HTTP2_Frame]) -> None:
        if type(frames) == list:
            for frame in frames:
                self.Namespace.Queue(frame)
        elif type(frames) == HTTP2_Frame:
            frame = frames
            if frame.StreamID == 0:
                if H2Flag.ACK in frame.Flags:
                    self.Namespace.ACKQueued.append(frame)
                    print(self)
                    print(self.Namespace.ACKQueued)
                else:
                    self.Namespace.ZeroQueued.append(frame)
            else:
                self.Namespace.Queued.append(frame)

    def ResetStream(self, sender, streamID: int, error: H2ErrorCode = H2ErrorCode.NO_ERROR):
        rst_stream = HTTP2_Frame(h2type=H2FrameType.RST_STREAM,
            streamID = streamID,
            payload  = error.value.to_bytes(4)
        )
        sender.send(rst_stream.Raw())

    def Shutdown(self, sender, error: H2ErrorCode = H2ErrorCode.NO_ERROR, debug_info: str = ""):
        goaway = HTTP2_Frame(h2type=H2FrameType.GOAWAY,
            payload = self.Namespace.Last_StreamID.to_bytes(4) + error.value.to_bytes(4) + debug_info.encode()
        )
        sender.send(goaway.Raw())
        self.Connection.close()

    def isACK(self, frame: HTTP2_Frame, ping: bytes = b'') -> bool:
        if ping:
            return frame.Type == H2FrameType.PING and frame.Flags == H2Flag.ACK and frame.Payload == self.Namespace.PingSequence
        else:
            return frame == SETTINGS_ACK

    def AwaitACK(self, sender, ping: bytes = b''):
        timeout = self.Namespace.Timeout
        if ping and len(ping) != 8:
            self.Shutdown(sender, H2ErrorCode.INTERNAL_ERROR, "Ping sequence must be 8 bytes")
        while True:
            print(self)
            print(self.Namespace.ACKQueued)
            if timeout > 0:
                for i, frame in enumerate(self.Namespace.ACKQueued):
                    if self.Namespace.isACK(frame, ping):
                        self.Namespace.ACKQueued.pop(i)
                        return
            else:
                self.Shutdown(sender, H2ErrorCode.SETTINGS_TIMEOUT, ("PING" if ping else "SETTINGS") + " Frame wasn't Acknowledged")
                return
            timeout-=1
            time.sleep(1)

    def Ping(self, sender) -> None:
        self.Namespace.PingSequence = os.urandom(8)
        ping = HTTP2_Frame(h2type=H2FrameType.PING,
            payload=self.Namespace.PingSequence
        )
        sender.send(ping.Raw())

    def SendSettings(self, sender) -> None:
        settings = HTTP2_Frame(h2type = H2FrameType.SETTINGS,
            payload = self.SettingsRaw()
        )
        sender.send(settings.Raw())

    def Preface(self, sender, request_str: str = ":method=GET;:path=/;:scheme=http;:authority=localhost:3000") -> bytes:
        _ = b''
        if self.Namespace.Server:
            preamble = self.Connection.recv(24)
            if preamble != PREAMBLE:
                self.Shutdown(sender, H2ErrorCode.PROTOCOL_ERROR, "Invalid Client Preface")
            frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(65535))
            settings = frames[0]
            if settings.Type == H2FrameType.SETTINGS:
                for name, value in settings.ParsePayload().items():
                    self.Namespace.Settings[name] = value
            else:
                self.Shutdown(sender, H2ErrorCode.PROTOCOL_ERROR, "Invalid Client Preface")
            self.Namespace.Queue(frames[1:])
            
            settings = HTTP2_Frame(h2type=H2FrameType.SETTINGS,
                payload = self.SettingsRaw()
            )
            sender.send(settings.Raw() + SETTINGS_ACK.Raw())
            process = mp.Process(target=self.AwaitACK)
            process.start()            

            print("Connection Established.\n\nQueue:")
        else:
            settings = HTTP2_Frame (h2type=H2FrameType.SETTINGS,
                payload = self.SettingsRaw()
            )
            request = HTTP2_Frame (h2type=H2FrameType.HEADERS,
                payload = self.Namespace.ParseHeadersFromString(request_str),
                flags   = H2Flag.END_HEADERS | H2Flag.END_STREAM,
                streamID= 1
            )
            
            sender.send(PREAMBLE + settings.Raw() + request.Raw())
            process = mp.Process(target=self.AwaitACK, args=[sender])
            process.start()
            
            def AwaitSettings(n=2) -> bool:
                if n == 0:
                    return False
                frames, _ = HTTP2_Frame.ParseRaw(self.Connection.recv(65535))
                self.Namespace.Queue(frames)
                for frame in self.Namespace.ZeroQueued:
                    if frame.Type == H2FrameType.SETTINGS:
                        sender.send(SETTINGS_ACK.Raw())
                        self.SetSettingsTable(frame.ParsePayload()) 
                        return True
                else:
                    return AwaitSettings(n-1)
            if not AwaitSettings():
                self.Shutdown(sender, H2ErrorCode.PROTOCOL_ERROR, "Invalid Server Preface")
        if self.Namespace.WindowSelf > 65535:
            update = self.Namespace.WindowSelf-65535
            if update >  2**31-1:
                window_updates = []
                x=2**31-1
                while update > x:
                    window_updates.append(HTTP2_Frame(h2type=H2FrameType.WINDOW_UPDATE, payload=(x).to_bytes(4)))
                    update-=x
                window_updates.append(HTTP2_Frame(h2type=H2FrameType.WINDOW_UPDATE, payload=update.to_bytes(4)))
                self.Send(sender, window_updates)
            else:
                window_update = HTTP2_Frame(h2type=H2FrameType.WINDOW_UPDATE, payload=update.to_bytes(4))
                self.Send(sender, window_update)
                
        return _

    def SendDATA(self, sender, frame: HTTP2_Frame):
        if frame.Type != H2FrameType.DATA:
            raise H2StreamError(H2ErrorCode.INTERNAL_ERROR, frame.StreamID)

        stream = self.Namespace.Streams[frame.StreamID]
        if frame.Length > self.Namespace.WindowPeer:
            while frame.Payload != b'':
                while self.Namespace.WindowPeer == 0 or stream.WindowPeer == 0:
                    print("Waiting for window increment..")
                    time.sleep(0.01)
                window = stream.WindowPeer
                chunk_frame = HTTP2_Frame(h2type=H2FrameType.DATA, payload=frame.Payload[:window], streamID=frame.StreamID)
                frame.WritePayload(frame.Payload[window:])
                if frame.Length == 0 and H2Flag.END_STREAM in frame.Flags:
                    frame.Flags = frame.Flags | H2Flag.END_STREAM
                print(chunk_frame.RawFormat())
                self.Send(sender, chunk_frame)
            
    
    def Send(self, sender, frame: HTTP2_Frame|list[HTTP2_Frame]) -> None:
        if type(frame) == HTTP2_Frame:
            if frame.StreamID == 0:
                sender.send(frame.Raw())
            else:
                match frame.Type:
                    case H2FrameType.HEADERS | H2FrameType.PUSH_PROMISE | H2FrameType.CONTINUATION:
                        if frame.Length > self.Namespace.GetSetting(H2Setting.MAX_FRAME_SIZE):
                            # self.Namespace.Hpack.DivideHeaders(size, padding) ?
                            ''
                        else:
                            sender.send(frame.Raw())
                            self.Namespace.Streams[frame.StreamID].Send(frame)
                    case H2FrameType.DATA:
                        if frame.Length > self.Namespace.Streams[frame.StreamID].WindowPeer:
                            proc = mp.Process(target=self.SendDATA, args=[sender, frame])
                            proc.run()
                        else:
                            self.Namespace.Streams[frame.StreamID].Send(frame)
                            sender.send(frame.Raw())

    def Loopback(self, sender, requestHandler) -> None:
        _ = self.Preface(sender)
        while True:
            if self.Namespace.Server:
                frames, _ = HTTP2_Frame.ParseRaw(_+self.Connection.recv(65535))
                for frame in frames:
                    print(frame.RawFormat(prefix='  '))
                    print()
                self.Namespace.Queue(frames)
                for frame in self.Namespace.ZeroQueued:
                    match frame.Type:
                        case H2FrameType.SETTINGS:
                            try:
                                self.SetSettingsTable(frame.ParsePayload())
                                self.Send(sender, SETTINGS_ACK)
                            except ValueError:
                                ''
                        case H2FrameType.PING:
                            ping_ack = HTTP2_Frame(h2type=H2FrameType.PING,payload=frame.Payload)
                            self.Send(sender, ping_ack)
                        case H2FrameType.WINDOW_UPDATE:
                            self.Namespace.WindowPeer += frame.ParsePayload()
                for frame in self.Namespace.Queued:
                    match frame.Type:
                        case H2FrameType.WINDOW_UPDATE:
                            self.Namespace.Streams[frame.StreamID].WindowPeer += frame.ParsePayload()

    def Init(self, requestHandler):
        sender, server = mp.Pipe()
        mp.Process(target=self.Loopback, args=[server, requestHandler])

        # Handling connection on the main HTTP2_Connection process
        while True:
            raw = sender.recv()
            self.Connection.send(raw)

if __name__ == "__main__":
    data = os.urandom(70000)
    serv = socket.socket()
    serv.bind(('localhost',3000))
    serv.listen(1)
    conn, addr = serv.accept()
    print(f"{addr[0]}:{addr[1]} has established Connection.")
    Conn = HTTP2_Connection(conn)
    def requestHandler(Conn, sender, req):
        
