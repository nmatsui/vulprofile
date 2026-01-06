# VulProfile
複数の脆弱性を内包する、学習用のPython Webアプリです。SQLインジェクション、XSS、CSRF等の脆弱性を内包しています。  
**脆弱性の学習用にのみ利用してください。実際のプロジェクトとして利用してはいけません。**

# Requirements
* Python >=3.12
  * Python 3.12 の標準ライブラリのみ利用しています。DjangoやFlask等のWebフレームワークは利用していません。

# Usage
1. Pythonのバージョンを確認する（3.12以上を推奨）

```
% python --version
```
2. sqlite3のテーブルを作成する

```
% python initdb.py
```
3. Webアプリを起動する

```
% python main.py
```
4. ブラウザから http://localhost:8000 へアクセスする

# License
"VulProfile" is under [MIT license](LICENSE)
