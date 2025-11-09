rm nginx.*
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout nginx.key \
  -out nginx.crt \
  -subj "/CN=myserver.com"
