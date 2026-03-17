# Wordlists

All wordlists live directly under:

```
src/wordlists/
```

Expected filenames used by plugins:

```
sql_injection.txt
xss.txt
directory_traversal.txt
command_injection.txt
ssrf.txt
open_redirect.txt
auth_bypass.txt
api_misconfig.txt
file_upload.txt
```

If files are missing, plugins fall back to built-in safe payloads.
