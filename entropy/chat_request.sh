#!/bin/bash
echo "$(date +'%Y-%m-%d %H:%M:%S') Starting curl request..."

curl -v "https://api.openai.com/v1/chat/completions"   -H "Authorization: Bearer $OPENAI_API_KEY"   -H "Content-Type: application/json"   -d '{"model": "gpt-4o", "messages": [{"role":"user","content":"test"}]}'

echo "$(date +'%Y-%m-%d %H:%M:%S') Curl request finished."