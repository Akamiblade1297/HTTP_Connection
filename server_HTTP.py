import socket
import errno
import os
import time
import threading
from datetime import datetime, timezone
import gzip, zlib, brotli
from pathlib import Path
from modules.http import HTTP, DATEFORMAT, CWD, Etags
HOST = '127.0.0.1'
PORT = 3000
CHUNK_SIZE = 65536
CHUNK_DELAY = 0.01
ENCODING = [
        "gzip",
        "deflate",
        "br",
        ]
LOGS = Path(f"logs/{datetime.strftime(datetime.now(),'%Y-%d-%m-_%H:%M:%S')}")
LOGS.touch()

def GetModifiedTime(path: Path) -> datetime:
    return datetime.fromtimestamp(os.path.getmtime(path.as_posix())).astimezone(timezone.utc).replace(microsecond=0)

def TimeFromString(string: str) -> datetime:
    return datetime.strptime(string, DATEFORMAT).replace(tzinfo=timezone.utc)

def SendResponse(conn: socket.socket, response: HTTP) -> None:
    if len(response.Body) > CHUNK_SIZE:
        print("Response body is large. Sending it in Chunks.")
        Body = response.Body
        response.SetBody('')
        conn.send(response.RawBytes())
        if type(Body) == str: Body = Body.encode()
        for i in range(0, len(Body), CHUNK_SIZE):
            conn.send( Body[ i : i + CHUNK_SIZE] )
            time.sleep(CHUNK_DELAY)
    else:
        conn.send(response.RawBytes())

def Handle_Request(conn: socket.socket, addr: tuple) -> None:
    conn.settimeout(5)
    try:
        while True:
            data = conn.recv(4096)
            try: request = HTTP(data.decode())
            except:
                print(f"Got non-HTTP request: {data}")
                break
            response = HTTP(None)
            print(f"Request from {addr[0]}:{addr[1]}:", ' '.join(request.StartLine))
            LOGS.write_text(LOGS.read_text() + f"Request from {addr[0]}:{addr[1]}:\n---\n" + request.Raw()+'---\n\n')

            # Processing Method request
            if request.StartLine[2].split('/')[0] != "HTTP":
                response.StatusCode(400)
            elif request.StartLine[2].split('/')[1] not in ["1.0", "1.1"]:
                response.StatusCode(505)
            elif request.StartLine[0] == "GET" or request.StartLine[0] == "HEAD":
                path = Path(f"./Web/{request.StartLine[1][1:]}")
                if path.as_posix() == 'Web':
                    response.StatusCode(200)
                    response.SetHeader("Content-Type", "text/html")
                    path = Path('Web/index.html')
                elif path.as_posix() == 'Web/music.mp3':
                    response.StatusCode(200)
                    response.SetHeader("Content-Type", "audio/mpeg")
                    response.SetHeader("Content-Disposition", "attachment")
                elif path.as_posix() == 'Web/Wordle':
                    response.StatusCode(200)
                    response.SetHeader("Content-Type", "text/html")
                    path = Path('Web/wordle.html')
                elif not path.resolve().as_posix().startswith(f"{CWD}Web/"): # Helding Directory Traversal
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
                            if request.GetHeader("If-None-Match") != '':
                                if Etags.GetETag(path) != request.GetHeader("If-None-Match"):
                                    response.GetBody(path, request.GetHeader("Range"))
                                else:
                                    response.StatusCode(304)
                            elif request.GetHeader("If-Match") != '':
                                if Etags.GetETag(path) == request.GetHeader("If-Match"):
                                    response.GetBody(path, request.GetHeader("Range"))
                                else:
                                    response.StatusCode(412)
                            elif request.GetHeader("If-Modified-Since") != '':
                                if TimeFromString(request.GetHeader("If-Modified-Since")) >= GetModifiedTime(path):
                                    response.GetBody(path, request.GetHeader("Range"))
                                else:
                                    response.StatusCode(304)
                            elif request.GetHeader("If-Unmodified-Since") != '':
                                if TimeFromString(request.GetHeader("If-Unmodified-Since")) >= GetModifiedTime(path):
                                    response.GetBody(path, request.GetHeader("Range"))
                                else:
                                    response.StatusCode(412)
                            else:
                                response.GetBody(path, request.GetHeader("Range"))
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
                print(f"Connection closed with {addr[0]}:{addr[1]}")
            else:
                if len(response.Body) > 128 and request.GetHeader('Accept-Encoding') != '':
                    if len(response.Body) > 128 and request.GetHeader('Accept-Encoding') != '':
                        Accepted = request.GetHeader("Accept-Encoding").split(', ')
                        if response.GetHeader("Content-Type").split('/') not in ['image/png', 'audio/mpeg']:
                            for i in ENCODING:
                                if i in Accepted:
                                    response.SetHeader("Content-Encoding", i)
                                    if type(response.Body) == str:
                                        response.SetBody(response.Body.encode())
                                    break
                            match response.GetHeader("Content-Encoding"):
                                case "gzip":
                                    response.SetBody(gzip.compress(response.Body, compresslevel=5))
                                case "deflate":
                                    response.SetBody(zlib.compress(response.Body, level=5))
                                case "br":
                                    response.SetBody(brotli.compress(response.Body, quality=5))
                            response.CalculateLength()

                if request.GetHeader("Connection").lower() in [ 'keep-alive', '' ]:
                    response.SetHeader("Connection", "keep-alive")
                    response.SetHeader("Keep-Alive", "timeout=5")
                    SendResponse(conn, response)
                    LOGS.write_text(LOGS.read_text() + f"Response for {addr[0]}:{addr[1]}:\n---\n" + response.Raw()+'\n---\n\n')
                    continue
                else:
                    response.SetHeader("Connection", "close")
                    conn.send(response.RawBytes())
                    conn.close()
                    print(f"Connection closed with {addr[0]}:{addr[1]}")
            LOGS.write_text(LOGS.read_text() + f"Response for {addr[0]}:{addr[1]}:\n---\n" + response.Raw()+'\n---\n\n')
            return

    except TimeoutError:
        print(f"Connection closed with {addr[0]}:{addr[1]} via timeout")
    except OSError as e:
        if e.errno == errno.ENAMETOOLONG:
            response = HTTP(None)
            response.StatusCode(414)
            response.SetHeader("Connection", "Close")
            conn.send(response.RawBytes())
    except Exception as err:
        print(f"Connection closed with {addr[0]}:{addr[1]} via unexpected Error: {err}")
    conn.close()

def Handle_Connection(server: socket.socket) -> None:
    conn, addr = server.accept()
    print(f"Connection established with {addr[0]}:{addr[1]}")
    # Handle_Request(conn, addr)
    client_thread = threading.Thread(target=Handle_Request, args=(conn, addr))
    client_thread.start()

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
