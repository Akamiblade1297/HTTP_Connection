from pathlib import Path
import os
import hashlib
from datetime import datetime, timezone
sha1 = hashlib.sha1()

CWD = Path.cwd().as_posix() + '/'
DATEFORMAT = "%a, %d %b %Y %H:%M:%S %Z"
CODES = {
        200: "OK",
        204: "No Content",
        304: "Not Modified", 400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Not Allowed",
        412: "Precondition Failed",
        414: "URI Too Long",
        505: "HTTP Version Not Supported",
}

ETagDB = Path('.ETags')
ETagDB.touch()

class HTTP:
    def __init__(self, raw: str|None = None) -> None:
        self.StartLine: list = []
        self.Headers:   dict = {}
        self.Body:     bytes = b""
        if type(raw) == str:
            raw_lines = raw.replace('\r','').split('\n')

            self.StartLine = raw_lines[0].split(' ')
            if len(self.StartLine) != 3:
                raise TypeError("Not valid HTTP Request")
            raw_lines.pop(0)

            keyNval = raw_lines[0].split(': ')
            while len(keyNval) == 2:
                self.SetHeader(keyNval[0], keyNval[1])
                raw_lines.pop(0)
                keyNval = raw_lines[0].split(': ')

            raw_lines.pop(0)
            self.Body = '\r\n'.join(raw_lines).encode()
        else:
            self.StartLine = ["HTTP/1.1", "", ""]

            self.SetHeader(  "Date"             ,   datetime.now(timezone.utc).strftime(DATEFORMAT)  )
            self.SetHeader(  "Connection"       ,   "keep-alive"                                     )
            self.SetHeader(  "Keep-Alive"       ,   ""                                               )
            self.SetHeader(  "Cache-Control"    ,   "public, max-age=86400"                          )
            self.SetHeader(  "X-Powered-By"     ,   "A97 the Cube"                                   )
            self.SetHeader(  "Content-Type"     ,   ""                                               )
            self.SetHeader(  "Content-Length"   ,   ""                                               )

    def CalculateLength(self) -> None:
        self.SetHeader("Content-Length", str(len( self.Body )))

    def SetHeader(self, header: str, value: str) -> None:
        self.Headers[header] = value

    def GetHeader(self, header: str) -> str:
        try:
            return self.Headers[header]
        except:
            return ""

    def StatusCode(self, code: int) -> None:
        if self.StartLine[0] == "HTTP/1.1":
            self.StartLine[1],self.StartLine[2] = str(code),CODES[code]
        else:
            raise TypeError("Can't assign Status Code to HTTP Request. It's for Response only")

    def _GenerateETag(self, path: Path) -> str:
        sha1.update(path.read_bytes())
        return sha1.hexdigest()

    def GetETag(self, path: Path) -> str:
        # ETags database contains ETags in format '<Relative path to file> <Last Modified Time> <ETag>'
        etags = ETagDB.read_text().split('\n')
        relpath = path.as_posix().replace(CWD, '') 
        modtime = str(os.path.getmtime(path.as_posix()))
        for i in range(len(etags)): 
            info = etags[i].split(' ')
            if info[0] == relpath: # Check if there's info about file we need in ETags database
                if info[1] == modtime: # Check if info is valid
                    return info[2]
                else:
                    # Update info if it's invalid
                    info[1] = modtime
                    info[2] = self._GenerateETag(path)
                    etags[i] = ' '.join(info)
                    ETagDB.write_text('\n'.join(etags))
                    return info[1]
        # If there's no info about the file, create it
        newETag = self._GenerateETag(path)
        etags.append(f"{relpath} {modtime} {newETag}")
        ETagDB.write_text('\n'.join(etags))
        return newETag

    def SetBody(self, body: str|bytes) -> None:
        if type(body) == str:
            self.Body = body.encode()
        elif type(body) == bytes:
            self.Body = body
        else:
            raise TypeError(f"Can't assing Body of type '{type(body)}' to HTTP Body")

    def GetBody(self, path: Path, ranges: str = '') -> None:
        if self.GetHeader("Content-Type") == "":
            raise AttributeError("Can't assign body from file. Can't get file MIME Type")

        self.SetBody(path.read_bytes())
        self.SetHeader("ETag", self.GetETag(path))

        # if ranges != '':

        self.CalculateLength()

    def Raw(self) -> str:
        raw_lines = [' '.join(self.StartLine)]
        for i in self.Headers.keys():
            if self.GetHeader(i) != "":
                raw_lines.append(f"{i}: {self.GetHeader(i)}")
        raw_lines.append('')
        if type(self.Body) == str:
            raw_lines.append(self.Body)
        elif len(self.Body) > 0:
            raw_lines.append(f"[{self.GetHeader('Content-Length')} Bytes of data]")

        raw = '\r\n'.join(raw_lines)
        return raw

    def RawBytes(self) -> bytes:
        raw_lines = [' '.join(self.StartLine)]
        for i in self.Headers.keys():
            if self.GetHeader(i) != "":
                raw_lines.append(f"{i}: {self.GetHeader(i)}")
        raw_lines.append('')
        raw = '\r\n'.join(raw_lines)

        raw_bytes = raw.encode()
        if type(self.Body) == str: self.Body = self.Body.encode()
        raw_bytes += b"\r\n" + self.Body
        return raw_bytes

if __name__ == "__main__":
    a = HTTP("""GET / HTTP/1.1\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\nUser-Agent: CubicHTTP/1.0\r\nHost: localhost:3000\r\n\r\n""")
    print(a.Raw())
    b = HTTP(None)
    b.SetHeader("Connection", "Keep-Alive")
    b.SetHeader("Keep-Alive", "timeout=5")
    b.Body = "Hello, from server!\r\n"
    b.CalculateLength()
    b.StatusCode(200)
    print(b.Raw())
