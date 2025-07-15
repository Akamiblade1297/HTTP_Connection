# What is that about?
I'm trying to recreate HTTP and HTTPS connection from scratch for educational purpose.  
I'm using [python-socket](https://docs.python.org/3/library/socket.html) package to use TCP Transport Layer, so I'm building HTTP Application Layer fully from scratch.
## How to launch?
`python server_HTTP.py`.  
## Things to do
 * HTTP **[✓]**  
    * ETags support **[✓]**  
    * Cache support **[✓]**  
    * Pipelining support **[✓]**  
    * Attachment support **[✓]**  
    * Ranges support **[✓]**  
    * Server **[✓]**
 * HTTP/2 **[WIP]**  
    * HPACK **[✓]**  
    * Frames **[✓]**  
    * Streams **[✓]**  
    * Connection **[WIP]** 
 * HTTPS  
    * TLS
    * Server
## Tools I used for understanding HTTP
[Wireshark](https://www.wireshark.org/download.html) to check HTTP packages and how should it look like.  
[Nodejs](https://nodejs.org) with [Express](https://expressjs.com/) to create HTTP server and check out how it works.  
[HTTPie CLI](https://httpie.io/docs/cli/installation) for forming HTTP Requests and Responses.  
[Grok](https://grok.com) for asking stupid questions *(never VibeCoded btw.)*  
## Refs for useful info about HTTP
[Alek OS Video](https://www.youtube.com/watch?v=EAqrn9debZ0) (Russian)  
[Mozilla HTTP Documentation](https://developer.mozilla.org/ru/docs/Web/HTTP)
[Habr HTTP/2 Documentation](https://habr.com/ru/companies/timeweb/articles/751338/) (Russian)
[IANA HTTP/2 Parameters](https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml)
[RFC 9113 HTTP/2 Documentation](https://www.rfc-editor.org/rfc/rfc9113.html#name-continuation)
[RFC 7541 HPACK Documentation](https://httpwg.org/specs/rfc7541.html)
