-- example HTTP POST script which demonstrates setting the
-- HTTP method, body, and adding a header

wrk.method = "POST"
wrk.body   = '{"id": "root", "secret": "GL5T_HZh7NEsA-90zzC6rN5aIsF3eLQOJmfmEcHD1SM="}'
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"