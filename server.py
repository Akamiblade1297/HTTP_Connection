import socket
# import asyncio
from pathlib import Path
from http_class import HTTP
HOST = '127.0.0.1'
PORT = 3000

def Handle_Request(conn: socket.socket, addr: tuple) -> None:
    data = 0
    data = conn.recv(1024)
    if data == b'': return
    request = HTTP(data.decode())
    response = HTTP(None)
    print(f"Request from {addr[0]}:{addr[1]}:", ' '.join(request.Headers))
    if request.Headers[2] != "HTTP/1.0":
        response.StatusCode(505)
    elif request.Headers[0] == "GET" or request.Headers[0] == "HEAD":
        path = Path(request.Headers[1][1:])
        print(path.as_posix())
        if path.as_posix() == '.':
            response.StatusCode(200)
            response.Content_Type = "text/html"
            path = Path('index.html')
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

    conn.send(response.RawBytes())
    print("Connection closed")
    conn.close()

def Handle_Connection(server: socket.socket) -> None:
    conn, addr = server.accept()
    print(f"Connection established with {addr[0]}:{addr[1]}")
    Handle_Request(conn, addr)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)
print(f"Listening on {HOST}:{PORT}..")
try: 
    while True: Handle_Connection(server)
except: server.close()
server.close()
