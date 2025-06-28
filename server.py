import socket
from pathlib import Path
from http_class import HTTP
CWD = Path('.').absolute().as_posix()
HOST = '127.0.0.1'
PORT = 3000

def Handle_Request(conn: socket.socket, addr: tuple) -> None:
    conn.settimeout(5)
    while True:
        data = conn.recv(4096)
        try: request = HTTP(data.decode())
        except:
            print(f"Got non-HTTP request: {data}")
            break
        response = HTTP(None)
        print(f"Request from {addr[0]}:{addr[1]}:", ' '.join(request.Headers))

        # Processing Method request
        if request.Headers[2] not in ["HTTP/1.0", "HTTP/1.1"]:
            response.StatusCode(505)
        elif request.Headers[0] == "GET" or request.Headers[0] == "HEAD":
            path = Path(request.Headers[1][1:])
            if path.as_posix() == '.':
                response.StatusCode(200)
                response.Content_Type = "text/html"
                path = Path('index.html')
            elif len(path.absolute().as_posix()) < len(CWD) or path.absolute().as_posix()[:len(CWD)] != CWD or '..' in path.as_posix():
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
                    response.Body = Path('ErrorPages/404.html').read_text()
                    response.CalculateLength()
            if request.Headers[0] == "GET":
                match response.Headers[1]:
                    case "200":
                        match response.Content_Type.split('/')[0]:
                            case "text":
                                response.Body = path.read_text()
                                response.CalculateLength()
                            case "image":
                                response.Body = path.read_bytes()
                                response.CalculateLength()
                    case "403":
                        response.Body = Path('ErrorPages/403.html').read_text()
                        response.CalculateLength()
        elif request.Headers[0] == "OPTIONS":
            response.StatusCode(204)
            response.Allow = "GET, HEAD, OPTIONS"
        elif request.Headers[0] in ["DELETE","TRACE","PUT","POST","CONNECT","PATCH"]:
            response.StatusCode(405)
        else:
            response.StatusCode(400)

        # Processing Connection type
        if request.Headers[2] == "HTTP/1.0":
            conn.send(response.RawBytes())
            conn.close()
            return
        elif not hasattr(request, 'Connection') or request.Connection.lower() == 'keep-alive':
            response.Connection = "Keep-Alive"
            response.Keep_Alive = "timeout=5"
            conn.send(response.RawBytes())
        else:
            request.Connection.lower() == 'close':
            response.Connection = "Close"
            conn.send(response.RawBytes())
            conn.close()
            return


def Handle_Connection(server: socket.socket) -> None:
    conn, addr = server.accept()
    print(f"Connection established with {addr[0]}:{addr[1]}")
    try: Handle_Request(conn, addr)
    except TimeoutError:
        print("Connection closed via timeout")
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
