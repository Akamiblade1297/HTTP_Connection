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
            response.SetHeader("Connection", "Close")
            conn.send(response.RawBytes())
            conn.close()
            break
        response = HTTP(None)
        print(f"Request from {addr[0]}:{addr[1]}:", ' '.join(request.StartLine))
        LOGS.write_text(LOGS.read_text() + f"Request from {addr[0]}:{addr[1]}:\n---\n" + request.Raw()+'---\n\n')

        # Processing Method request
        if request.StartLine[2] not in ["HTTP/1.0", "HTTP/1.1"]:
            response.StatusCode(505)
        elif request.StartLine[0] == "GET" or request.StartLine[0] == "HEAD":
            path = Path(f"./Web/{request.StartLine[1][1:]}")
            print(path)
            if path.as_posix() == 'Web':
                response.StatusCode(200)
                response.SetHeader("Content-Type", "text/html")
                path = Path('Web/index.html')
            elif path.as_posix() == 'Web/music.mp3':
                response.StatusCode(200)
                response.SetHeader("Content-Type", "audio/mpeg")
                response.SetHeader("Content-Disposition", "attachment")
            elif not path.resolve().as_posix().startswith(CWD): # Helding Directory Traversal
                response.StatusCode(400)
                response.SetHeader("Content-Type", "text/html")
            elif Path(path).exists():
                response.StatusCode(200)
                match Path(path).suffix:
                    case ".css":
                        response.SetHeader("Content-Type", "text/css")
                    case ".html":
                        response.SetHeader("Content-Type", "text/html")
                    case ".js":
                        response.SetHeader("Content-Type", "text/javascript")
                    case ".png":
                        response.SetHeader("Content-Type", "image/png")
                    case ".ico":
                        response.SetHeader("Content-Type", "image/x-icon")
                    case _:
                        response.StatusCode(403)
                        response.SetHeader("Content-Type", "text/html")

            else:
                response.StatusCode(404)
                response.SetHeader("Content-Type", "text/html")
            if request.StartLine[0] == "GET":
                match response.StartLine[1]:
                    case "200":
                        if hasattr(request, "If-None-Match"):
                            if response.GetETag(path) != request.GetHeader("If-None-Match"):
                                response.GetBody(path)
                            else:
                                response.StatusCode(304)
                        elif hasattr(request, "If-Match"):
                            if response.GetETag(path) == request.GetHeader("If-Match"):
                                response.GetBody(path)
                            else:
                                response.StatusCode(412)
                        elif hasattr(request, "If-Modified-Since"):
                            if TimeFromString(request.GetHeader("If-Modified-Since")) >= GetModifiedTime(path):
                                response.GetBody(path)
                            else:
                                response.StatusCode(304)
                        elif hasattr(request, "If-Unmodified-Since"):
                            if TimeFromString(request.GetHeader("If-Unmodified-Since")) >= GetModifiedTime(path):
                                response.GetBody(path)
                            else:
                                response.StatusCode(412)
                        else:
                            response.GetBody(path)
                    case "403":
                        response.GetBody(Path('ErrorPages/403.html'))
                    case "404":
                        response.GetBody(Path('ErrorPages/404.html'))

        elif request.StartLine[0] == "OPTIONS":
            response.StatusCode(204)
            response.SetHeader("Allow", "GET, HEAD, OPTIONS")
        elif request.StartLine[0] in ["DELETE","TRACE","PUT","POST","CONNECT","PATCH"]:
            response.StatusCode(405)
        else:
            response.StatusCode(400)

        # Processing Connection type and body compression
        if request.StartLine[2] == "HTTP/1.0":
            conn.send(response.RawBytes())
            conn.close()
            print("Connection closed")
        else:
            if len(response.Body) > 128 and request.GetHeader('Accept-Encoding') != '':
                if len(response.Body) > 128 and request.GetHeader('Accept-Encoding') != '':
                    Accepted = request.GetHeader("Accept-Encoding").split(', ')
                    if response.GetHeader("Content-Type").split('/') not in ['image/png', 'audio/mpeg']:
                        for i in ENCODING:
                            if i in Accepted:
                                response.SetHeader("Content-Encoding", i)
                                if type(response.Body) == str:
                                    response.Body = response.Body.encode()
                                break
                        match response.GetHeader("Content-Encoding"):
                            case "gzip":
                                response.Body = gzip.compress(response.Body, compresslevel=5)
                            case "deflate":
                                response.Body = zlib.compress(response.Body, level=5)
                            case "br":
                                response.Body = brotli.compress(response.Body, quality=5)
                        response.CalculateLength()

            if request.GetHeader("Connection").lower() in [ 'keep-alive', '' ]:
                response.SetHeader("Connection", "keep-alive")
                response.SetHeader("Keep-Alive", "timeout=5")
                conn.send(response.RawBytes())
                LOGS.write_text(LOGS.read_text() + f"Response for {addr[0]}:{addr[1]}:\n---\n" + response.Raw()+'\n---\n\n')
                continue
            else:
                response.SetHeader("Connection", "close")
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
            response.SetHeader("Connection", "Close")
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
print(f"Logs was saved in {LOGS.resolve().as_posix()}")
server.close()
