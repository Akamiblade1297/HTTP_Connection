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
        206: "Partial Content",
        304: "Not Modified",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Not Allowed",
        412: "Precondition Failed",
        414: "URI Too Long",
        505: "HTTP Version Not Supported",
}
BOUNDARY = "SUper==SigMaCubicB04ndary97"
ETagDB = Path('.ETags')
ETagDB.touch()

class Etags:
    @staticmethod
    def GenerateETag(path: Path) -> str:
        sha1.update(path.read_bytes())
        return sha1.hexdigest()

    @staticmethod
    def GetETag(path: Path) -> str:
        # ETags database contains ETags in format '<Relative path to file> <Last Modified Time> <ETag>'
        etags = ETagDB.read_text().split('\n')
        relpath = path.as_posix().replace(CWD, '') 
        modtime = str(os.path.getmtime(path.as_posix()))
        for i in range(len(etags)): 
            info = etags[i].split(' ')
            if info[0] == relpath: # Check if there's info about file we need in ETags database
                if info[1] == modtime: # Check if info is outdated
                    return info[2]
                else:
                    # Update if info is outdated
                    info[1] = modtime
                    info[2] = Etags.GenerateETag(path)
                    etags[i] = ' '.join(info)
                    ETagDB.write_text('\n'.join(etags))
                    return info[1]
        # If there's no info about the file, create it
        newETag = Etags.GenerateETag(path)
        etags.append(f"{relpath} {modtime} {newETag}")
        ETagDB.write_text('\n'.join(etags))
        return newETag    

class HTTP:
    def __init__(self, raw: str|None = None) -> None:
        self.StartLine: list = []
        self.Headers:   dict = {}
        self.Body:     bytes = b""
        if type(raw) == str:
            raw_lines = raw.replace('\r','').split('\n')

            self.StartLine = raw_lines[0].split(' ')
            if len(self.StartLine) != 3:
                raise ValueError("Not valid HTTP Request")
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
            self.SetHeader(  "Accept-Ranges"    ,   "bytes"                                          )
            self.SetHeader(  "Content-Type"     ,   ""                                               )
            self.SetHeader(  "Content-Range"    ,   ""                                               )
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

    def GetRange(self, body: bytes, rng: list[str]) -> bytes:
        if len(rng) != 2:
            raise ValueError("Invalid range given")
        try:
            i_rng = list(map(int, rng))
            return body[ i_rng[0] : i_rng[1] ] 
        except ValueError as e:
            if rng[0] == '' and rng[1] == '':
                raise ValueError("Invalid range given")
            elif rng[0] == '':
                return body[             : int(rng[1]) ]
            elif rng[1] == '':
                return body[ int(rng[0]) :             ]
            else:
                raise e

    def SetBody(self, body: str|bytes) -> None:
        if type(body) == str:
            self.Body = body.encode()
        elif type(body) == bytes:
            self.Body = body
        else:
            raise TypeError(f"Can't assing Body of type '{type(body)}' to HTTP Body")

    def GetBody(self, path: Path, ranges_header: str = '', boundary: str = BOUNDARY) -> None:
        print(ranges_header)
        body = path.read_bytes()
        self.SetHeader("ETag", Etags.GetETag(path))

        if ranges_header != '' and ranges_header.split('=')[0] == 'bytes':
            self.StatusCode(206)
            ranges = ranges_header.split('=')[1].split(',')
            print(ranges)
            if len(ranges) == 1:
                rng = ranges[0].split('-')
                self.SetHeader("Content-Range", f"bytes {ranges[0]}/{len(body)}")
                self.SetBody(self.GetRange(body, rng))
            else:
                filetype = self.GetHeader("Content-Type")
                self.SetHeader("Content-Type", f"multipart/byteranges; boundary={boundary}")
                rangesBody = b""
                separator = f"--{boundary}\r\n"
                endline = f"--{boundary}--"
                
                for rng in ranges:
                    rng = rng.split('-')
                    rangeHeaders = f"{separator}Content-Type: {filetype}\r\nContent-Range: bytes {'-'.join(rng)}/{len(body)}\r\n\r\n"
                    rangesBody += rangeHeaders.encode() + self.GetRange(body, rng) + b"\r\n"
                rangesBody += endline.encode()
                self.SetBody(rangesBody)
        else:
            self.SetBody(body)

        self.CalculateLength()

    def Raw(self) -> str:
        raw_lines = [' '.join(self.StartLine)]
        for i in self.Headers.keys():
            if self.GetHeader(i) != "":
                raw_lines.append(f"{i}: {self.GetHeader(i)}")
        raw_lines.append('')
        if self.GetHeader("Content-Type").split('/')[0] == 'text':
            raw_lines.append(self.Body.decode())
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

    def __str__(self) -> str:
        return self.Raw()
