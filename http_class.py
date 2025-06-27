import datetime
import pytz

CODES = {
        200: "OK",
        204: "No Content",
        403: "Forbidden",
        404: "Not Found",
        405: "Not Allowed",
        505: "HTTP Version Not Supported",
}

class HTTP:
    def __init__(self, raw: str|None) -> None:
        if type(raw) == str:
            raw_lines = raw.replace('\r','').split('\n')

            self.Headers = raw_lines[0].split(' ')
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
            self.Headers        =   ["HTTP/1.0", "", ""]
            self.Content_Type   =   "text/html"
            self.Date           =    datetime.datetime.now().astimezone(pytz.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            self.X_Powered_By   =   "A97 the Cube"
            self.Body           =   ""

    def CalculateLength(self) -> None:
        self.Content_Length = str(len(self.Body))

    def StatusCode(self, code: int) -> None:
        if self.Headers[0].split('/')[0] == "HTTP":
            self.Headers[1],self.Headers[2] = str(code),CODES[code]
        else:
            raise AttributeError("Can't assign Status Code to HTTP Request. It's for Response only")

    def Raw(self) -> str:
        if type(self.Body != str): 
            raise TypeError("Can't get raw text, because the Body is Bytes class. Try using .RawBytes() method instead of .Raw()")
        raw_lines = [' '.join(self.Headers)]
        for i in self.__dict__.keys():
            if i != "Headers" and i != "Body":
                raw_lines.append(f"{i.replace('_','-')}: {self.__dict__[i]}")
        raw_lines.append('')
        raw_lines.append(self.Body)

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
