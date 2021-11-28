1. Default token period is 30s

2. How to use
```sh
./totp_tool.py --one-time

+--------+---------+
|  Name  | 2FA key |
+--------+---------+
| mytotp |  553002 |
+--------+---------+
```

3. When encrypted secret is used

```
# password: test
./totp_tool.py --one-time --config secret_encrypted.yaml --password

+--------+---------+
|  Name  | 2FA key |
+--------+---------+
| mytotp |  278128 |
+--------+---------+
```
