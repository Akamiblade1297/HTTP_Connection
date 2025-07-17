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
