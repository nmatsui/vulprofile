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
