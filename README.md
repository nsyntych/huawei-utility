# Huawei Password & Configuration Utility

A browser-based client-side utility suite for Huawei routers and CPE devices. All computations and decryptions run 100% locally in your browser.

**Live Website:** [https://nsyntych.github.io/huawei-utility/](https://nsyntych.github.io/huawei-utility/)

## Features

- **XML Config Decryptor**:
  - Drag & drop or browse your router backup XML configuration file (e.g. `hw_ctree.xml`) or paste raw XML.
  - Automatically recovers and decodes factory passwords (such as `admin`), user accounts, Wi-Fi WPA/WPA2 pre-shared keys, WPS PINs, CLI accounts, SSL cert passwords, and CWMP settings.
  - Instant live search and category filtering.
  - One-click copy for any password or all credentials.
  - "Download Decrypted XML" feature to export a clean, fully-decrypted XML configuration file.
  - "Export JSON" for structured credential backup.
- **Password Generator**:
  - Hashes passwords using Huawei router firmware modes (MD5, SHA256-MD5, PBKDF2-SHA256 with 5000 iterations).
- **Cipher / Decipher**:
  - Direct encryption and decryption of Huawei `$2...$` strings with automatic XML entity unescaping.

## ⚖️ Legal & Trademark Disclaimers

> [!IMPORTANT]
> **Trademark Notice:** "Huawei" and associated product names, model designations, and logos are registered trademarks of **Huawei Technologies Co., Ltd.** (or its subsidiaries/affiliates).
>
> This project is an independent open-source tool and is **not affiliated with, endorsed by, sponsored by, or officially connected to Huawei Technologies Co., Ltd.** Any references to the Huawei brand, router hardware, or firmware specifications are used solely for identification, compatibility, and descriptive purposes under nominative fair use.

## 🛡️ Responsible Use & ISP Policy

- **Educational & Diagnostic Use Only:** This tool is designed strictly for lawful network administration, diagnostics, educational research, and personal configuration recovery on routers that you legally own or are authorized to configure.
- **No Illegal Activity:** The authors and contributors do **not** condone, promote, or support any unlawful activities, unauthorized network access, or unauthorized modification of equipment.
- **ISP Terms of Service:** If your router or ONT/CPE device is leased or managed by an Internet Service Provider (ISP), modifying settings or recovering firmware credentials may be subject to your ISP's Terms of Service (ToS) or Acceptable Use Policy (AUP). Users are solely responsible for ensuring compliance with all applicable local laws, regulations, and provider agreements.
- **No Warranty ("AS IS"):** Provided under the GNU General Public License v3.0 without warranties of any kind. The authors and maintainers are not liable for any direct or indirect damages, lost data, bricked devices, ISP penalties, or legal consequences arising from the use of this utility.

For full legal disclosures, see [DISCLAIMER.md](DISCLAIMER.md).

## Credits & References

This project is a fork of the original work by **André Brandão ([@andreluis034](https://github.com/andreluis034)) / [Fayaru](https://blog.fayaru.me)**.

- **Original Author**: André Brandão (Fayaru)
- **Original Repository**: [andreluis034/huawei-utility-page](https://github.com/andreluis034/huawei-utility-page)
- **Technical Writeup**: [Huawei Router Configuration & Encryption Analysis by Fayaru](https://blog.fayaru.me/posts/huawei_router_config/)
- **License**: [GNU GPLv3](LICENSE)
