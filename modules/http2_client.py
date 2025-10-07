###########################################
### THE PURPOSE OF THIS FILE IS TESTING ###
###########################################
import socket
from http2 import *
from hpack import HPACK

client = socket.socket()
client.connect(('localhost',3000))

Connection = HTTP2_Connection(client, server=False)
Connection.SetSetting(H2Setting.MAX_CONCURENT_STREAMS, 100)
Connection.Preface(':method=GET;:scheme=http;:path=/;:authority=example.com;accept-language=ru;user-agent=CubicBrowser/9.7')

_ = b""
while True:
    recv = client.recv(9)
    print(recv)
    length = int.from_bytes(recv[:3])
    _ = recv
    recv = client.recv(length)
    frames, _ = HTTP2_Frame.ParseRaw(_ + recv)
    for frame in frames:
        print(frame.RawFormat())
        if frame.Type == H2FrameType.DATA:
            window_upd0 = HTTP2_Frame(h2type=H2FrameType.WINDOW_UPDATE, payload=frame.Length.to_bytes(4))
            window_upd = HTTP2_Frame(h2type=H2FrameType.WINDOW_UPDATE, payload=frame.Length.to_bytes(4), streamID=frame.StreamID)
            client.send(window_upd.Raw() + window_upd0.Raw())
    frames = []
