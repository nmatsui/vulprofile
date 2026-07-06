import sqlite3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from database import get_connection
from http_io import HttpRequest, HttpResponse
from templates import base_html, login_html, register_html, profile_html, update_html

server_address = "http://localhost:8000"


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
                with get_connection() as conn:
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
                with get_connection() as conn:
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

                with get_connection() as conn:
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

                check_sql = f"SELECT count(*) \
                              FROM users \
                              WHERE username='{username}'"
                insert_sql = f"INSERT INTO users (username, password, profile) \
                               VALUES ('{username}', '{password}', '{profile}')"

                duplicated = False
                try:
                    with get_connection() as conn:
                        cur = conn.cursor()
                        cur.execute(check_sql)
                        if cur.fetchone()[0] == 1:
                            duplicated = True
                        else:
                            cur.execute(insert_sql)
                except sqlite3.IntegrityError:
                    duplicated = True

                if duplicated:
                    body = register_html.format(errors=f"ユーザー名({username})は既に登録されています")
                    html = base_html.format(body=body)
                    response.ok_200(html)
                    return

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

                with get_connection() as conn:
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

                with get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute(sql)

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
    with ThreadingHTTPServer(('0.0.0.0', 8000), RequestHandler) as server:
        print(f"Starting server at {server_address}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped")
