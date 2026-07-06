from urllib.parse import parse_qs

SESSIONS = dict()
SESSION_ID = 1
SESSION_ID_KEY = "sid"


class HttpRequest:
    CONTENT_LENGTH_MAX = 8192

    def __init__(self, handler):
        self.handler = handler

    def __get_session_id(self):
        cookie_header = self.handler.headers.get("Cookie")
        if cookie_header:
            cookies = dict(item.split("=") for item in [x.strip() for x in cookie_header.split(";")] if "=" in item)
            return cookies.get(SESSION_ID_KEY)
        return None

    def new_session(self, data):
        global SESSION_ID
        SESSION_ID += 1
        session_id = str(SESSION_ID)
        SESSIONS[session_id] = data
        return session_id

    def get_session(self):
        session_id = self.__get_session_id()
        if session_id in SESSIONS:
            return SESSIONS[session_id]
        return None

    def remove_session(self):
        session_id = self.__get_session_id()
        if session_id in SESSIONS:
            del SESSIONS[session_id]

    def parse_body(self):
        content_length_str = self.handler.headers.get("content-length")
        if content_length_str is None:
            return dict()
        try:
            content_length = int(content_length_str)
        except ValueError:
            return dict()
        if content_length < 0 or content_length > self.CONTENT_LENGTH_MAX:
            return dict()
        body = self.handler.rfile.read(content_length).decode("utf-8", errors="replace")
        return parse_qs(body)


class HttpResponse:
    def __init__(self, handler):
        self.handler = handler
        self.headers = dict()

    def set_session_cookie(self, session_id):
        self.headers["Set-Cookie"] = f"{SESSION_ID_KEY}={session_id}; Max-Age=3600"

    def remove_session_cookie(self):
        self.headers["Set-Cookie"] = f"{SESSION_ID_KEY}=; Max-Age=0"

    def __respond(self, status_code, content_type, body_text):
        self.handler.send_response(status_code)
        self.handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
        for k, v in self.headers.items():
            self.handler.send_header(k, v)
        self.handler.end_headers()
        self.handler.wfile.write(body_text.encode())

    def ok_200(self, html, headers=None):
        self.__respond(200, "text/html", html)

    def found_302(self, location):
        self.handler.send_response(302)
        self.handler.send_header("Location", location)
        for k, v in self.headers.items():
            self.handler.send_header(k, v)
        self.handler.end_headers()

    def bad_request_400(self):
        self.__respond(400, "text/plain", "400 Bad Request")

    def unauthorized_401(self):
        self.remove_session_cookie()
        self.__respond(401, "text/plain", "401 Unauthorized")

    def not_found_404(self):
        self.__respond(404, "text/plain", "404 Not Found")

    def conflict_409(self):
        self.remove_session_cookie()
        self.__respond(409, "text/plain", "409 Conflict")
