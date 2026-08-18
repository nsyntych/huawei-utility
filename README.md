# Huawei Password & Configuration Utility

A browser-based client-side utility suite for Huawei routers and CPE devices. All computations and decryptions run 100% locally in your browser.

## Features

- **XML Config Decryptor**:
  - Drag & drop or browse your router backup XML configuration file (e.g. `hw_ctree.xml`) or paste raw XML.
  - Automatically recovers and decodes factory passwords (such as `Nova_admin`), user accounts, Wi-Fi WPA/WPA2 pre-shared keys, WPS PINs, CLI accounts, SSL cert passwords, and CWMP settings.
  - Instant live search and category filtering.
  - One-click copy for any password or all credentials.
  - "Download Decrypted XML" feature to export a clean, fully-decrypted XML configuration file.
  - "Export JSON" for structured credential backup.
- **Password Generator**:
  - Hashes passwords using Huawei router firmware modes (MD5, SHA256-MD5, PBKDF2-SHA256 with 5000 iterations).
- **Cipher / Decipher**:
  - Direct encryption and decryption of Huawei `$2...$` strings with automatic XML entity unescaping.

## Credits & References

This project is a fork of the original work by **André Brandão ([@andreluis034](https://github.com/andreluis034)) / [Fayaru](https://blog.fayaru.me)**.

- **Original Author**: André Brandão (Fayaru)
- **Original Repository**: [andreluis034/huawei-utility-page](https://github.com/andreluis034/huawei-utility-page)
- **Technical Writeup**: [Huawei Router Configuration & Encryption Analysis by Fayaru](https://blog.fayaru.me/posts/huawei_router_config/)

