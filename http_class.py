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
        304: "Not Modified",
        400: "Bad Request",
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
    def __init__(self, raw: str|None) -> None:
        if type(raw) == str:
            raw_lines = raw.replace('\r','').split('\n')

            self.Headers = raw_lines[0].split(' ')
            if len(self.Headers) != 3:
                raise TypeError("Not valid HTTP Request")
            raw_lines.pop(0)

            keyNval = ['','']
            while len(keyNval) != 1:
                keyNval = raw_lines[0].split(': ')
                try: self.__dict__[keyNval[0].replace('-','_')] = keyNval[1]
                except: ''
                raw_lines.pop(0)

            raw_lines.pop(0)
            self.Body = '\r\n'.join(raw_lines)
        else:
            self.Headers        =   ["HTTP/1.1", "", ""]
            self.Date           =   datetime.now(timezone.utc).strftime(DATEFORMAT)
            self.Connection     =   "Keep-Alive"
            self.X_Powered_By   =   "A97 the Cube"
            self.Body           =   ""

    def CalculateLength(self) -> None:
        self.Content_Length = str(len(self.Body))

    def StatusCode(self, code: int) -> None:
        if self.Headers[0] == "HTTP/1.1":
            self.Headers[1],self.Headers[2] = str(code),CODES[code]
        else:
            raise TypeError("Can't assign Status Code to HTTP Request. It's for Response only")

    def _GenerateETag(self, path: Path) -> str:
        sha1.update(path.read_bytes())
        return sha1.hexdigest()

    def GetETag(self, path: Path) -> str:
        # ETags database contains ETags in format '<Relative path to file> <Last Modified Time> <ETag>'
        etags = ETagDB.read_text().split('\n')
        relpath = path.as_posix().replace(CWD, '') 
        print(relpath)
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

    def GetBody(self, path: Path) -> None:
        if not "Content_Type" in self.__dict__.keys():
            raise AttributeError("Can't assign body from file. Can't get file MIME Type")
        match self.Content_Type.split('/')[0]:
            case "text":
                self.Body = path.read_text()
            case "image":
                self.Body = path.read_bytes()
            case _:
                raise AttributeError("Can't assign body from file. File HIME Type not supported")
        self.ETag = self.GetETag(path)
        self.CalculateLength()

    def Raw(self) -> str:
        raw_lines = [' '.join(self.Headers)]
        for i in self.__dict__.keys():
            if i != "Headers" and i != "Body":
                raw_lines.append(f"{i.replace('_','-')}: {self.__dict__[i]}")
        raw_lines.append('')
        if type(self.Body) == str:
            raw_lines.append(self.Body)
        else:
            raw_lines.append("Binary Data")

        raw = '\r\n'.join(raw_lines)
        return raw

    def RawBytes(self) -> bytes:
        raw_lines = [' '.join(self.Headers)]
        for i in self.__dict__.keys():
            if i != "Headers" and i != "Body":
                raw_lines.append(f"{i.replace('_','-')}: {self.__dict__[i]}")
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
    b.Connection = "Keep-Alive"
    b.Keep_Alive = "timeout=5"
    b.Body = "Hello, from server!\r\n"
    b.CalculateLength()
    b.StatusCode(200)
    print(b.Raw())
