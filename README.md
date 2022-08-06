# Defender Detection Sync
A quick and dirty way to synchronize defender detection rules across multiple tenants. This project utilizes the apiproxy `https://security.microsoft.com/apiproxy/mtp/huntingService/rules/` (undocumented, which makes sense), and supports session authentication only.

Usage:
1. Log in to security.microsoft.com with an account from the tenant you wish to synchronize detection rules from
2. Extract the XSRF and SCCAUTH tokens using developer tools and add them to `config.json`
3. Repeat step one and two using an account from the domain you wish to synchonize to
4. Run `python3 main.py`
