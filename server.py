import socket
import errno
import os
from datetime import datetime, timezone
import gzip, zlib, brotli
from pathlib import Path
from http_class import HTTP, DATEFORMAT, CWD
HOST = '127.0.0.1'
PORT = 3000
ENCODING = [
        "gzip",
        "deflate",
        "br",
        ]
LOGS = Path(f"logs/{datetime.strftime(datetime.now(),'%Y-%m-%d_%H:%M:%S')}")
LOGS.touch()

def GetModifiedTime(path: Path) -> datetime:
    return datetime.fromtimestamp(os.path.getmtime(path.as_posix())).astimezone(timezone.utc).replace(microsecond=0)

def TimeFromString(string: str) -> datetime:
    return datetime.strptime(string, DATEFORMAT).replace(tzinfo=timezone.utc)

def Handle_Request(conn: socket.socket, addr: tuple) -> None:
    conn.settimeout(5)
    while True:
        data = conn.recv(4096)
        try: request = HTTP(data.decode())
        except:
            print(f"Got non-HTTP request: {data}")
            response = HTTP(None)
            response.StatusCode(400)
            response.Connection = "Close"
            conn.send(response.RawBytes())
            conn.close()
            break
        response = HTTP(None)
        print(f"Request from {addr[0]}:{addr[1]}:", ' '.join(request.Headers))
        LOGS.write_text(LOGS.read_text() + f"Request from {addr[0]}:{addr[1]}:\n---\n" + request.Raw()+'---\n\n')

        # Processing Method request
        if request.Headers[2] not in ["HTTP/1.0", "HTTP/1.1"]:
            response.StatusCode(505)
        elif request.Headers[0] == "GET" or request.Headers[0] == "HEAD":
            path = Path(request.Headers[1][1:])
            if path.as_posix() == '.':
                response.StatusCode(200)
                response.Content_Type = "text/html"
                path = Path('index.html')
            elif not path.resolve().as_posix().startswith(CWD): # Helding Directory Traversal
                response.StatusCode(400)
                response.Content_Type = "text/html"
            elif Path(path).exists():
                response.StatusCode(200)
                match Path(path).suffix:
                    case ".css":
                        response.Content_Type = "text/css"
                    case ".html":
                        response.Content_Type = "text/html"
                    case ".js":
                        response.Content_Type = "text/javascript"
                    case ".png":
                        response.Content_Type = "image/png"
                    case ".ico":
                        response.Content_Type = "image/x-icon"
                    case _:
                        response.StatusCode(403)
                        response.Content_Type = "text/html"

            else:
                response.StatusCode(404)
                response.Content_Type = "text/html"
            if request.Headers[0] == "GET":
                match response.Headers[1]:
                    case "200":
                        if hasattr(request, "If_None_Match"):
                            if response.GetETag(path) != request.If_None_Match:
                                response.GetBody(path)
                            else:
                                response.StatusCode(304)
                        elif hasattr(request, "If_Match"):
                            if response.GetETag(path) == request.If_Match:
                                response.GetBody(path)
                            else:
                                response.StatusCode(412)
                        elif hasattr(request, "If_Modified_Since"):
                            if TimeFromString(request.If_Modified_Since) >= GetModifiedTime(path):
                                response.GetBody(path)
                            else:
                                response.StatusCode(304)
                        elif hasattr(request, "If_Unmodified_Since"):
                            if TimeFromString(request.If_Unmodified_Since) >= GetModifiedTime(path):
                                response.GetBody(path)
                            else:
                                response.StatusCode(412)
                        else:
                            response.GetBody(path)
                    case "403":
                        response.GetBody(Path('ErrorPages/403.html'))
                    case "404":
                        response.GetBody(Path('ErrorPages/404.html'))

        elif request.Headers[0] == "OPTIONS":
            response.StatusCode(204)
            response.Allow = "GET, HEAD, OPTIONS"
        elif request.Headers[0] in ["DELETE","TRACE","PUT","POST","CONNECT","PATCH"]:
            response.StatusCode(405)
        else:
            response.StatusCode(400)

        # Processing Connection type and body compression
        if request.Headers[2] == "HTTP/1.0":
            conn.send(response.RawBytes())
            conn.close()
            print("Connection closed")
        else:
            if len(response.Body) > 128 and hasattr(request, 'Accept_Encoding'):
                Accepted = request.Accept_Encoding.split(', ')
                for i in ENCODING:
                    if i in Accepted:
                        response.Content_Encoding = i
                        if type(response.Body) == str:
                            response.Body = response.Body.encode()
                        break

                l = len(response.Body)
                match response.Content_Encoding:
                    case "gzip":
                        if l < 10240 or response.Content_Type.split('/')[0] == 'image':
                            response.Body = gzip.compress(response.Body, compresslevel=3)
                        elif l < 1048576:
                            response.Body = gzip.compress(response.Body, compresslevel=5)
                        elif l < 1048576000:
                            response.Body = gzip.compress(response.Body, compresslevel=7)
                        else:
                            response.Body = gzip.compress(response.Body, compresslevel=9)
                    case "deflate":
                        if l < 10240 or response.Content_Type.split('/')[0] == 'image':
                            response.Body = zlib.compress(response.Body, level=3)
                        elif l < 1048576:
                            response.Body = zlib.compress(response.Body, level=5)
                        elif l < 1048576000:
                            response.Body = zlib.compress(response.Body, level=7)
                        else:
                            response.Body = zlib.compress(response.Body, level=9)
                    case "br":
                        if l < 10240 or response.Content_Type.split('/')[0] == 'image':
                            response.Body = brotli.compress(response.Body, quality=3)
                        elif l < 1048576:
                            response.Body = brotli.compress(response.Body, quality=5)
                        elif l < 1048576000:
                            response.Body = brotli.compress(response.Body, quality=7)
                        else:
                            response.Body = brotli.compress(response.Body, quality=9)
                response.CalculateLength()

            if not hasattr(request, 'Connection') or request.Connection.lower() == 'keep-alive':
                response.Connection = "Keep-Alive"
                response.Keep_Alive = "timeout=5" 
                conn.send(response.RawBytes())
                LOGS.write_text(LOGS.read_text() + f"Response for {addr[0]}:{addr[1]}:\n---\n" + response.Raw()+'\n---\n\n')
                continue
            else:
                response.Connection = "Close"
                conn.send(response.RawBytes())
                conn.close()
                print("Connection closed")
        LOGS.write_text(LOGS.read_text() + f"Response for {addr[0]}:{addr[1]}:\n---\n" + response.Raw()+'\n---\n\n')
        return

def Handle_Connection(server: socket.socket) -> None:
    conn, addr = server.accept()
    print(f"Connection established with {addr[0]}:{addr[1]}")
    try: Handle_Request(conn, addr)
    except TimeoutError:
        print("Connection closed via timeout")
    except OSError as e:
        if e.errno == errno.ENAMETOOLONG:
            response = HTTP(None)
            response.StatusCode(414)
            response.Connection = "Close"
            conn.send(response.RawBytes())
    except Exception as err:
        print(f"Connection closed via unexpected Error: {err}")
    conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
server.bind((HOST, PORT))
server.listen(5)
print(f"Listening on {HOST}:{PORT} in {CWD}..")
try: 
    while True: Handle_Connection(server)
except KeyboardInterrupt:
    print("\nServer was interrupted and closed manually")
except Exception as err:
    print(f"Server was closed via unexpected Error: {err}")
server.close()
