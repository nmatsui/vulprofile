import sqlite3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

DBNAME = "db.sqlite3"
server_address = "http://localhost:8000"


base_html = """
<!DOCTYPE html>
<html lang="ja">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>脆弱性テスト</title>
  </head>
  <body>
    {body}
  </body>
</html>
"""

login_html = """
    <form action="/login" method="post">
      <table>
        <tr>
          <th>ユーザー名</th><td><input type="text" id="username" name="username" required /></td>
        </tr>
        <tr>
          <th>パスワード</th><td><input type="text" id="password" name="password" required /></td>
        </tr>
      </table>
      <div>
        <input type="submit" id="login" name="login" value="ログイン"/>
      </div>
      <div>
        <span id="errors">{errors}</span>
      </div>
    </form>
    <a href="/register">登録</a>
"""

register_html = """
    <form action="/register" method="post">
      <table>
        <tr>
          <th>ユーザー名</th><td><input type="text" id="username" name="username" required /></td>
        </tr>
        <tr>
          <th>パスワード</th><td><input type="text" id="password" name="password" required /></td>
        </tr>
        <tr>
          <th>プロフィール</th><td><input type="textarea" id="profile" name="profile" /></td>
        </tr>
      </table>
      <div>
        <input type="submit" id="register" name="register" value="登録"/>
      </div>
      <div>
        <span id="errors">{errors}</span>
      </div>
    </form>
    <div>
      <a href="/login">戻る</a>
    </div>
"""

profile_html = """
    <table>
      <tr>
        <th>ユーザー名</th><td>{username}</td>
      </tr>
      <tr>
        <th>プロフィール</th><td>{profile}</td>
      </tr>
    </table>
    <div>
      <a href="/update">更新</a>
    </div>
    <form action="/logout" method="post">
      <input type="submit" id="logout" name="logout" value="ログアウト"/>
    </form>
"""

update_html = """
    <form action="/update" method="post">
      <table>
        <tr>
            <th>ユーザー名</th><td>{username}</td>
        </tr>
        <tr>
          <th>パスワード</th><td><input type="text" id="password" name="password" value="{password}" required /></td>
        </tr>
        <tr>
          <th>プロフィール</th><td><input type="textarea" id="profile" name="profile" value="{profile}" /></td>
        </tr>
      </table>
      <div>
        <input type="submit" id="register" name="register" value="更新"/>
      </div>
    </form>
    <div>
      <a href="/profile">戻る</a>
    </div>
"""


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


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = HttpRequest(self)
        response = HttpResponse(self)
        match urlparse(self.path).path:
            case "/":
                response.found_302("/login")
                return

            case "/login":
                body = login_html.format(errors="")
                html = base_html.format(body=body)
                response.ok_200(html)
                return

            case "/register":
                body = register_html.format(errors="")
                html = base_html.format(body=body)
                response.ok_200(html)
                return

            case "/profile":
                session = request.get_session()
                if session is None or "username" not in session:
                    response.unauthorized_401()
                    return

                username = session.get("username")
                sql = f"SELECT username, profile \
                        FROM users \
                        WHERE username='{username}'"
                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    record = cur.fetchone()

                if not record:
                    response.conflict_409()
                    return

                body = profile_html.format(username=username, profile=record[1])
                html = base_html.format(body=body)
                response.ok_200(html)
                return

            case "/update":
                session = request.get_session()
                if session is None or "username" not in session:
                    response.unauthorized_401()
                    return

                username = session.get("username")
                sql = f"SELECT username, password, profile \
                        FROM users \
                        WHERE username='{username}'"
                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    record = cur.fetchone()

                if not record:
                    response.conflict_409()
                    return

                body = update_html.format(username=username, password=record[1], profile=record[2])
                html = base_html.format(body=body)
                response.ok_200(html)
                return

            case _:
                response.not_found_404()
                return

    def do_POST(self):
        request = HttpRequest(self)
        response = HttpResponse(self)
        match urlparse(self.path).path:
            case "/login":
                params = request.parse_body()
                if params is None or "username" not in params or "password" not in params:
                    response.bad_request_400()
                    return

                username = params["username"][0]
                password = params["password"][0]
                sql = f"SELECT count(*) \
                        FROM users \
                        WHERE username='{username}' AND password='{password}'"

                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    record = cur.fetchone()

                if record[0] == 0:
                    body = login_html.format(errors=f"ユーザー名({username})かパスワードが間違っています")
                    html = base_html.format(body=body)
                    response.ok_200(html)
                    return

                session_id = request.new_session({
                    "username": username,
                })
                response.set_session_cookie(session_id)
                response.found_302("/profile")
                return

            case "/register":
                params = request.parse_body()
                if params is None or "username" not in params or "password" not in params or "profile" not in params:
                    response.bad_request_400()
                    return

                username = params["username"][0]
                password = params["password"][0]
                profile = params["profile"][0]

                sql = f"SELECT count(*) \
                        FROM users \
                        WHERE username='{username}'"

                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    record = cur.fetchone()

                if record[0] == 1:
                    body = register_html.format(errors=f"ユーザー名({username})は既に登録されています")
                    html = base_html.format(body=body)
                    response.ok_200(html)
                    return

                sql = f"INSERT INTO users (username, password, profile) \
                        VALUES ('{username}', '{password}', '{profile}')"

                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    conn.commit()

                response.found_302("/login")
                return

            case "/update":
                session = request.get_session()
                if session is None or "username" not in session:
                    response.unauthorized_401()
                    return

                username = session.get("username")
                sql = f"SELECT count(*) \
                        FROM users \
                        WHERE username='{username}'"

                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    record = cur.fetchone()

                if record[0] != 1:
                    response.conflict_409()
                    return

                params = request.parse_body()
                if params is None or "password" not in params or "profile" not in params:
                    response.bad_request_400()
                    return

                password = params["password"][0]
                profile = params["profile"][0]

                sql = f"UPDATE users \
                        SET password='{password}', profile='{profile}' \
                        WHERE username='{username}'"

                with sqlite3.connect(DBNAME) as conn:
                    cur = conn.cursor()
                    cur.execute(sql)
                    conn.commit()

                response.found_302("/profile")
                return

            case "/logout":
                request.remove_session()
                response.remove_session_cookie()
                response.found_302("/login")
                return

            case _:
                response.not_found_404()
                return


if __name__ == '__main__':
    with HTTPServer(('0.0.0.0', 8000), RequestHandler) as server:
        print(f"Starting server at {server_address}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped")
