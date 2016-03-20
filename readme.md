simple websocket chat
=====================

features
---------
* use on Windows OS
* made by python
* websocket chat over the LAN

attention
----------
* this program is websocket sample program
* it has some bad security issues

usage
------
1. install python
2. download this program
3. change ipaddress, port number to  index.html, socket_server.py
4. run webserver(change ipaddress, port number)

```
python -c "import BaseHTTPServer as bhs, SimpleHTTPServer as shs; bhs.HTTPServer(('192.168.1.1', 8888), shs.SimpleHTTPRequestHandler).serve_forever()"
```

5. run websocket server

```
python socket_server.py
```