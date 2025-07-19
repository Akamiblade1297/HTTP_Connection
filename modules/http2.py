import socket, os
import threading
from enum import Enum, Flag, auto
from typing import Any, Callable, Self
from hpack import HPACK, CompressionError
from datetime import datetime, timezone
from http import HTTP, DATEFORMAT, CODES, Etags

PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class H2FrameType(Enum):
    UNDEFINED       = -1
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

class H2ConnectionError(Exception):
    def __init__(self, code: H2ErrorCode, DebugInfo: str = '') -> None:
        message = f"{hex(code.value)} {code.name} {DebugInfo}"
        self.Code = code.value
        self.message = message

class H2StreamError(Exception):
    def __init__(self, code: H2ErrorCode, DebugInfo: str = '') -> None:
        message = f"{hex(code.value)} {code.name} {DebugInfo}"
        self.Code = code.value
        self.message = message

class HTTP2_Frame:
    def __init__(self, h2type: H2FrameType = H2FrameType(-1), flags: H2Flag|int = H2Flag(0), streamID: int = 0, payload: bytes = b'', padding: int = 0, hpack: HPACK = HPACK()) -> None:
        self.Hpack    :HPACK       = hpack
        self.Length   :int         = 0
        self.Type     :H2FrameType = h2type
        self.Flags    :H2Flag      = flags if type(flags) == H2Flag else self.ParseFlags(flags, self.Type)
        self.StreamID :int         = streamID
        self.Padding  :int         = padding
        self.Payload  :bytes       = payload

        self.CalculateLength()

        if self.StreamID > 2**31-1:
            raise ValueError("StreamID Can't be larger then 2^31-1")
        if H2Flag.PADDED in self.Flags and self.Padding >= self.Length:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Pad Length must be less then than Payload Length")
    #################
    #### FACTORY ####
    #################
    def __new__(cls, *args, **kwargs) -> object:
        if len(args) == 0:
            if 'h2type' not in kwargs.keys():
                raise ValueError("'h2type' Keyword Argument of type 'H2FrameType' or 1 Positional Argument of type 'bytes' expected")
            return object.__new__(eval(f"HTTP2_{kwargs['h2type'].name}"))
        elif len(args) == 1 and type(args[0]) == bytes:
            parsed_kwargs = HTTP2_Frame.__ParseRawFrame(args[0])
            parsed_kwargs['hpack'] = kwargs['hpack']
            return HTTP2_Frame.__new__(cls, **parsed_kwargs)
        else:
            raise ValueError("'h2type' Keyword Argument of type 'H2FrameType' or 1 Positional Argument of type 'bytes' expected")
    #################
    #### FACTORY ####
    #################
    @staticmethod
    def __ParseRawFrame(raw: bytes) -> dict[str,Any]:
        Length   = int.from_bytes(raw[:3])
        H2type   = H2FrameType(raw[3])
        Flags    = HTTP2_Frame.ParseFlags(raw[4], H2type)
        StreamID = int.from_bytes(raw[5:9])
        
        if H2Flag.PADDED in Flags:
            Padding = raw[9]
            Payload = raw[10:]
        else:
            Padding = 0
            Payload = raw[9:]

        if StreamID > 2**31-1     : raise ValueError("Stream ID Can't be larger then 2^31-1")
        if len(Payload) != Length : raise ValueError("Length field doesn't match the actual Payload length")

        return {
                'h2type'   : H2type   ,
                'flags'    : Flags    ,
                'streamID' : StreamID ,
                'padding'  : Padding  ,
                'payload'  : Payload  ,
               }

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

    def CalculateLength(self) -> None:
        self.Length = len(self.Payload) + ( self.Padding + 1 if H2Flag.PADDED in self.Flags else 0)
 
    def RawFlags(self) -> int:
        flagsRaw = 0
        for flag in self.Flags:
            flagsRaw += flag.value if flag != H2Flag.ACK else 1
        return flagsRaw

    def ParsePayload(self) -> Any:
        return "UNDEFINED"

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

    @staticmethod
    def formatdecorator(func: Callable) -> Callable:
        def wrapper(frame, prefix = '') -> str:
            raw_lines = [ f"{prefix}{frame.Type.name}/{frame.StreamID}" ]
            for flag in frame.Flags:
                raw_lines.append(f"+ {flag.name}")
            raw_lines: list[str] = func(frame, prefix, raw_lines)
            return ('\n    ' + prefix).join(raw_lines)

        return wrapper

    @formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        raw_lines.append("UNDEFINED")
        return raw_lines

    def __eq__(self, other) -> bool:
        if type(other) != HTTP2_Frame:
            raise TypeError(f"Can't compare HTTP2_Frame to {type(other)}")
        return (other.Raw() == self.Raw())

class HTTP2_DATA(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID == 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "DATA Frame must differ from 0")

    def ParsePayload(self) -> bytes:
        return self.Payload

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        raw_lines.append(f"[{self.Length} bytes of Data]")
        return raw_lines

class HTTP2_HEADERS(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID == 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "HEADERS Frame StreamID must differ from 0")

    def ParsePayload(self) -> dict[str,str]:
        return self.Hpack.DecodeHeaders(self.Payload)

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]: 
        headers = self.ParsePayload()
        raw_lines += HTTP2_Frame.FormatHeaders(headers) 
        return raw_lines

class HTTP2_RST_STREAM(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID != 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "RST_STREAM Frame StreamID must be set to 0")
        elif self.Length != 4:
            raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "RST_STREAM Frame Payload Length must be 4 Octets long")

    def ParsePayload(self) -> H2ErrorCode:
        return H2ErrorCode(int.from_bytes(self.Payload))

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        error = self.ParsePayload()

        raw_lines.append(f"{error.value} {error.name}")
        return raw_lines

class HTTP2_SETTINGS(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID != 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "SETTINGS Frame StreamID must be set to 0")
        elif H2Flag.ACK in self.Flags and self.Length > 0:
            raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS Frame Payload with ACK Flag must be empty")
        elif self.Length % 6 != 0:
            raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS Frame Payload Length must be a multiple of 6")

    def ParsePayload(self) -> dict[int,int]:
        settings = {}
        i,j = 0,2
        while j < len(self.Payload):
            setting = int.from_bytes(self.Payload[i:j])
            i,j = j,j+4
            value = int.from_bytes(self.Payload[i:j])
            settings[setting] = value
            i,j = j,j+2
        return settings

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        settings = self.ParsePayload()

        for setting, value in settings.items():
            raw_lines.append(f"{H2Setting(setting).name} = {value}")
        return raw_lines

class HTTP2_PUSH_PROMISE(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID == 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE Frame StreamID must differ from 0")

    def ParsePayload(self) -> tuple[int,dict[str,str]]:
        promised_streamID = int.from_bytes(self.Payload[:4])
        headers           = self.Hpack.DecodeHeaders(self.Payload[4:])
        return (promised_streamID, headers)
    
    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        promised_streamID, headers = self.ParsePayload() 

        raw_lines.append(f"Promissed-Stream-ID: {promised_streamID}")
        raw_lines += HTTP2_Frame.FormatHeaders(headers)
        return raw_lines

class HTTP2_PING(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID != 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "PING Frame StreamID must be set to 0")
        elif self.Length != 8:
            raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "PING Frame Payload Length must be 8 Octets long")

    def ParsePayload(self) -> bytes:
        return self.Payload

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        data = self.ParsePayload()
        raw_lines.append(' '.join([ f"{x:02X}" if (i+1)%4 != 0 else f"{x:02X} " for i,x in enumerate(data) ]))
        return raw_lines

class HTTP2_GOAWAY(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self.StreamID != 0:
            raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "GOAWAY Frame StreamID must be set to 0")
    def ParsePayload(self) -> tuple[int,H2ErrorCode]:
        last_streamID = int.from_bytes(self.Payload[:4])
        error         = H2ErrorCode(self.Payload[4:])
        return (last_streamID, error)

    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        last_streamID, error = self.ParsePayload()
        raw_lines.append(f"Last-Stream-ID = {last_streamID}")
        raw_lines.append(f"{error.value} {error.name}")
        return raw_lines

class HTTP2_WINDOW_UPDATE(HTTP2_Frame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        increment = self.ParsePayload()
        if increment == 0:
            if self.StreamID == 0:
                raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Window Increment Size must differ from 0")
            else:
                raise H2StreamError(H2ErrorCode.PROTOCOL_ERROR, "Window Increment Size must differ from 0")
        elif self.Length != 4:
            raise H2ConnectionError(H2ErrorCode.FRAME_SIZE_ERROR, "WINDOU_UPDATE Frame Payload Lenght must be 4 Octets long")

    def ParsePayload(self) -> int:
        return int.from_bytes(self.Payload)
    
    @HTTP2_Frame.formatdecorator
    def RawFormat(self, prefix: str = '', raw_lines: list[str] = []) -> list[str]:
        increment = self.ParsePayload()
        raw_lines.append(f"Window Size Increment = {increment}")
        return raw_lines

class HTTP2_CONTINUATION(HTTP2_HEADERS):
    ''

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

class HTTP2_Connection:
    def __init__(self, conn: socket.socket, server: bool = True):
        self.Settings   :dict[int,int]     = {}
        self.Queued     :list[HTTP2_Frame] = []
        self.Hpack      :HPACK             = HPACK()
        self.Server     :bool              = server
        self.Connection :socket.socket     = conn
        self.Streams    :HTTP2_StreamList  = HTTP2_StreamList()
        
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
                    raise H2ConnectionError(H2ErrorCode.SETTINGS_TIMEOUT, "No ACK Frame received")
            except TimeoutError:
                raise H2ConnectionError(H2ErrorCode.SETTINGS_TIMEOUT, "No ACK Frame received")
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
                    raise H2ConnectionError(H2ErrorCode.SETTINGS_TIMEOUT, "No ACK Frame received")
            elif len(frames) == 2:
                if not ( frames[0].Type == H2FrameType.SETTINGS and frames[0].RawFlags() == 0 and frames[1] == ACK ):
                    raise H2ConnectionError(H2ErrorCode.PROTOCOL_ERROR, "Invalid Server Preface")
                for name, value in frames[0].ParsePayload():
                    self.Settings[name] = value
                self.Connection.send(ACK.Raw())

if __name__ == "__main__":
    hpack = HPACK()
    a = HTTP2_Frame(h2type=H2FrameType.SETTINGS,
        streamID = 1,

    )
    print(a.RawFormat())
    print()
    print(a.RawDump())
