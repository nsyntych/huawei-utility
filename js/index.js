// Constants & Web Worker Setup
const myWorker = new Worker('js/worker.js');
let sendToWorker = false;

// Global state for Decrypted XML Data
let currentXmlText = "";
let currentFileName = "hw_ctree.xml";
let decryptedItems = []; // Array of { id, category, categoryLabel, title, field, plainValue, cipherValue, rawValue, nodeInfo, isFeatured }
let activeCategory = "ALL";
let searchQuery = "";

// -------------------------------------------------------------
// Core Decryption Engine (AES-256-CBC Huawei Base-93 Algorithm)
// -------------------------------------------------------------
const BLOCK_SIZE = 0x14;

function HW_AES_AscUnvisible(encryptedStr) {
	let buf = new Uint8Array(encryptedStr.split('').map(c => c.charCodeAt(0)));
	for (let i = 0; i < buf.length; i++) {
		if (0x7e === buf[i]) { // character ~
			buf[i] = 0x1e;
		} else {
			buf[i] = buf[i] - 0x21; // character !
		}
	}
	return buf;
}

function HW_AES_AesEnhSysToLong(buffer) {
	let output = 0;
	let v3 = 1;
	for (let i = 0; i < 5; i++) {
		output += v3 * buffer[i];
		v3 *= 0x5D;
	}
	return output;
}

function HW_AES_PlainToBin(buffer) {
	if (buffer.length % 5 !== 0) return null;
	let output = new Uint8Array(buffer.length * 4 / 5);
	let periodFive = 0;
	for (let i = 0; i !== output.length; i += 4) {
		let _long = HW_AES_AesEnhSysToLong(buffer.slice(periodFive, periodFive + 5));
		for (let b = 0; b < 4; b++) {
			output[i + b] = (_long >> (8 * b)) & 0xFF;
		}
		periodFive += 5;
	}
	return output;
}

function HW_AES_Trim(encryptedStr) {
	if (!encryptedStr || encryptedStr.length < 3) return "";
	if (encryptedStr[0] !== "$" || encryptedStr[1] !== "2" || encryptedStr[encryptedStr.length - 1] !== "$") {
		return "";
	}
	return encryptedStr.substring(2, encryptedStr.length - 1);
}

const toHexString = bytes =>
	bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

/**
 * Decrypts any Huawei $2...$ ciphertext string.
 * Automatically handles XML/HTML unescaping (e.g. &amp;, &quot;, &apos;, &lt;, &gt;).
 */
function decryptHuaweiString(inputStr, keyHex = PASSWORD_HEX) {
	if (!inputStr || typeof inputStr !== 'string') return "";
	
	// Unescape HTML / XML entities
	let unescaped = inputStr;
	if (typeof he !== 'undefined' && he.decode) {
		unescaped = he.decode(inputStr.trim());
	} else {
		unescaped = inputStr.trim()
			.replace(/&quot;/g, '"')
			.replace(/&apos;/g, "'")
			.replace(/&lt;/g, '<')
			.replace(/&gt;/g, '>')
			.replace(/&amp;/g, '&');
	}

	let trimmed = HW_AES_Trim(unescaped);
	if (!trimmed) return "";

	let unvisible = HW_AES_AscUnvisible(trimmed);
	let blockCount = (unvisible.length / BLOCK_SIZE) >> 0;
	if (unvisible.length !== BLOCK_SIZE * blockCount || blockCount < 1) {
		return "";
	}

	let IV = HW_AES_PlainToBin(unvisible.slice(blockCount * BLOCK_SIZE - BLOCK_SIZE, blockCount * BLOCK_SIZE));
	let dataAll = HW_AES_PlainToBin(unvisible.slice(0, blockCount * BLOCK_SIZE - BLOCK_SIZE));
	if (!IV || !dataAll) return "";

	try {
		if (typeof CryptoJS !== 'undefined' && CryptoJS.AES) {
			let result = CryptoJS.AES.decrypt(toHexString(dataAll), CryptoJS.enc.Hex.parse(keyHex), {
				iv: CryptoJS.enc.Hex.parse(toHexString(IV)),
				mode: CryptoJS.mode.CBC,
				format: CryptoJS.format.Hex
			});
			result.sigBytes = dataAll.length;
			let utf8Str = result.toString(CryptoJS.enc.Utf8);
			// Clean trailing null padding bytes
			return utf8Str.replace(/\0+$/g, '');
		}
	} catch (e) {
		console.error("Decryption error:", e);
	}
	return "";
}

// -------------------------------------------------------------
// XML Parsing & Credential Extraction
// -------------------------------------------------------------
function isDummyPlaceholderPassword(plainValue, fieldName = "") {
	if (!plainValue) return true;
	const trimmed = String(plainValue).trim();
	if (trimmed.length === 0) return true;
	
	// Single repeated character of length >= 4 (e.g. aaaaaaaaaaaaa, bbbbbbbbbbbbb, 00000000, 11111111)
	if (/^(.)\1{3,}$/i.test(trimmed)) {
		return true;
	}
	// Common placeholder sequences in router firmware
	const placeholders = ["1234567890123", "abcdefghijklm", "0123456789012", "1234567890", "00000000", "11111111", "adminadmin", "passwordpassword"];
	if (placeholders.includes(trimmed.toLowerCase())) {
		return true;
	}
	// WEP default filler slots
	if (fieldName.toLowerCase().includes("wep") && trimmed.length >= 5 && /^([a-z0-9])\1+$/i.test(trimmed)) {
		return true;
	}
	return false;
}

function togglePasswordVisibility(elementId, btn) {
	const elem = document.getElementById(elementId);
	if (!elem) return;
	const isMasked = elem.getAttribute("data-masked") === "true";
	const plain = elem.getAttribute("data-plain") || "";

	if (isMasked) {
		elem.textContent = plain;
		elem.setAttribute("data-masked", "false");
		elem.classList.remove("masked");
		if (btn) {
			btn.classList.add("active");
			btn.title = "Hide password";
			btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
		}
	} else {
		elem.textContent = "••••••••••••";
		elem.setAttribute("data-masked", "true");
		elem.classList.add("masked");
		if (btn) {
			btn.classList.remove("active");
			btn.title = "Show password";
			btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
		}
	}
}

function parseAndDecryptXml(xmlString, fileName = "hw_ctree.xml", saveToHistory = true) {
	currentXmlText = xmlString;
	currentFileName = fileName;
	decryptedItems = [];

	let seenCiphertexts = new Set();
	let itemId = 0;

	const parser = new DOMParser();
	let xmlDoc;
	try {
		xmlDoc = parser.parseFromString(xmlString, "text/xml");
	} catch (e) {
		console.warn("DOMParser failed, will fallback to regex scanner:", e);
	}

	// 1. Web Users (<X_HW_WebUserInfoInstance>)
	if (xmlDoc) {
		const webUsers = xmlDoc.querySelectorAll("X_HW_WebUserInfoInstance");
		webUsers.forEach(user => {
			const userName = user.getAttribute("UserName") || user.getAttribute("Username") || "User";
			const factoryPass = user.getAttribute("FactoryPassword");
			const pass = user.getAttribute("Password");
			const salt = user.getAttribute("Salt") || "";
			const passMode = user.getAttribute("PassMode") || "";
			const alias = user.getAttribute("Alias") || "";
			const userLevel = user.getAttribute("UserLevel") || "";

			const isAdminUser = userName.toLowerCase().includes("admin");

			if (factoryPass && factoryPass.startsWith("$2")) {
				seenCiphertexts.add(factoryPass);
				const decrypted = decryptHuaweiString(factoryPass);
				decryptedItems.push({
					id: ++itemId,
					category: "WEB",
					categoryLabel: "Web User",
					title: userName,
					field: "FactoryPassword",
					plainValue: decrypted,
					cipherValue: factoryPass,
					isFeatured: true,
					isFactory: true,
					meta: { userName, userLevel, passMode, salt, alias }
				});
			}

			if (pass && pass.startsWith("$2")) {
				seenCiphertexts.add(pass);
				const decrypted = decryptHuaweiString(pass);
				decryptedItems.push({
					id: ++itemId,
					category: "WEB",
					categoryLabel: "Web User",
					title: userName,
					field: "Current Password (Hash/Plain)",
					plainValue: decrypted,
					cipherValue: pass,
					isFeatured: isAdminUser,
					isHash: decrypted.length === 64,
					meta: { userName, userLevel, passMode, salt, alias }
				});
			}

			// Sub-tags like IteratePassword or History
			const iterPass = user.querySelector("X_HW_IteratePassword");
			if (iterPass && iterPass.getAttribute("Password") && iterPass.getAttribute("Password").startsWith("$2")) {
				const cVal = iterPass.getAttribute("Password");
				seenCiphertexts.add(cVal);
				decryptedItems.push({
					id: ++itemId,
					category: "WEB",
					categoryLabel: "Web User",
					title: `${userName} (IteratePassword)`,
					field: "IteratePassword",
					plainValue: decryptHuaweiString(cVal),
					cipherValue: cVal,
					isHash: true,
					meta: { salt: iterPass.getAttribute("Salt"), count: iterPass.getAttribute("IterateCount") }
				});
			}
		});

		// 2. Wi-Fi / WLAN Networks (<WLANConfigurationInstance>)
		const wlanConfigs = xmlDoc.querySelectorAll("WLANConfigurationInstance");
		wlanConfigs.forEach(wlan => {
			const ssid = wlan.getAttribute("SSID") || wlan.getAttribute("Name") || "Wi-Fi";
			const name = wlan.getAttribute("Name") || "";
			const band = wlan.getAttribute("X_HW_RFBand") || wlan.getAttribute("Band") || "";

			// PreSharedKey
			const pskNodes = wlan.querySelectorAll("PreSharedKeyInstance");
			pskNodes.forEach(psk => {
				const cVal = psk.getAttribute("PreSharedKey");
				if (cVal && cVal.startsWith("$2")) {
					seenCiphertexts.add(cVal);
					decryptedItems.push({
						id: ++itemId,
						category: "WIFI",
						categoryLabel: "Wi-Fi Network",
						title: `SSID: "${ssid}" (${band || name})`,
						field: "PreSharedKey (WPA Key)",
						plainValue: decryptHuaweiString(cVal),
						cipherValue: cVal,
						isWifi: true,
						meta: { ssid, name, band }
					});
				}
			});

			// WPS DevicePassword
			const wpsNodes = wlan.querySelectorAll("WPS");
			wpsNodes.forEach(wps => {
				const cVal = wps.getAttribute("DevicePassword");
				if (cVal && cVal.startsWith("$2")) {
					seenCiphertexts.add(cVal);
					decryptedItems.push({
						id: ++itemId,
						category: "WIFI",
						categoryLabel: "Wi-Fi Network",
						title: `SSID: "${ssid}" (${band || name})`,
						field: "WPS PIN / Password",
						plainValue: decryptHuaweiString(cVal),
						cipherValue: cVal,
						isWifi: true,
						meta: { ssid, name, band }
					});
				}
			});

			// WEP Keys (Omit dummy repeated placeholders like aaaaaaaaaaaaa, bbbbbbbbbbbbb)
			const wepNodes = wlan.querySelectorAll("WEPKeyInstance");
			wepNodes.forEach(wep => {
				const cVal = wep.getAttribute("WEPKey");
				const instId = wep.getAttribute("InstanceID") || "";
				if (cVal && cVal.startsWith("$2")) {
					const decrypted = decryptHuaweiString(cVal);
					if (decrypted && !isDummyPlaceholderPassword(decrypted, "WEPKey")) {
						seenCiphertexts.add(cVal);
						decryptedItems.push({
							id: ++itemId,
							category: "WIFI",
							categoryLabel: "Wi-Fi Network",
							title: `SSID: "${ssid}" (WEP Key #${instId})`,
							field: `WEPKey #${instId}`,
							plainValue: decrypted,
							cipherValue: cVal,
							isWifi: true,
							meta: { ssid, name, band }
						});
					}
				}
			});

			// Radius Secret
			const radKey = wlan.getAttribute("X_HW_RadiusKey");
			if (radKey && radKey.startsWith("$2")) {
				const decrypted = decryptHuaweiString(radKey);
				if (decrypted && !isDummyPlaceholderPassword(decrypted, "X_HW_RadiusKey")) {
					seenCiphertexts.add(radKey);
					decryptedItems.push({
						id: ++itemId,
						category: "WIFI",
						categoryLabel: "Wi-Fi Network",
						title: `SSID: "${ssid}"`,
						field: "X_HW_RadiusKey",
						plainValue: decrypted,
						cipherValue: radKey,
						meta: { ssid, name, band }
					});
				}
			}
		});

		// 3. CLI Users (<X_HW_CLIUserInfoInstance>)
		const cliUsers = xmlDoc.querySelectorAll("X_HW_CLIUserInfoInstance");
		cliUsers.forEach(cli => {
			const username = cli.getAttribute("Username") || cli.getAttribute("UserName") || "CLI User";
			const userpass = cli.getAttribute("Userpassword") || cli.getAttribute("Password");
			const access = cli.getAttribute("AccessInterface") || "";
			const salt = cli.getAttribute("Salt") || "";

			if (userpass && userpass.startsWith("$2")) {
				seenCiphertexts.add(userpass);
				const decrypted = decryptHuaweiString(userpass);
				decryptedItems.push({
					id: ++itemId,
					category: "CLI",
					categoryLabel: "CLI Account",
					title: `CLI: ${username}`,
					field: "Userpassword",
					plainValue: decrypted,
					cipherValue: userpass,
					isHash: decrypted.length === 64,
					meta: { username, access, salt }
				});
			}
		});

		// 4. System & CWMP (<X_HW_ShellAuthInfo>, <X_HW_WebSslInfo>, <ManagementServer>)
		const shellNodes = xmlDoc.querySelectorAll("X_HW_ShellAuthInfo");
		shellNodes.forEach(node => {
			const pass = node.getAttribute("Password");
			if (pass && pass.startsWith("$2")) {
				seenCiphertexts.add(pass);
				decryptedItems.push({
					id: ++itemId,
					category: "SYSTEM",
					categoryLabel: "System Auth",
					title: "Shell Authentication",
					field: "Shell Password",
					plainValue: decryptHuaweiString(pass),
					cipherValue: pass,
					meta: { tag: "X_HW_ShellAuthInfo" }
				});
			}
		});

		const sslNodes = xmlDoc.querySelectorAll("X_HW_WebSslInfo");
		sslNodes.forEach(node => {
			const pass = node.getAttribute("CertPassword");
			if (pass && pass.startsWith("$2")) {
				seenCiphertexts.add(pass);
				decryptedItems.push({
					id: ++itemId,
					category: "SYSTEM",
					categoryLabel: "System Auth",
					title: "Web SSL Certificate",
					field: "CertPassword",
					plainValue: decryptHuaweiString(pass),
					cipherValue: pass,
					meta: { tag: "X_HW_WebSslInfo" }
				});
			}
		});

		const mgmtNodes = xmlDoc.querySelectorAll("ManagementServer");
		mgmtNodes.forEach(node => {
			const url = node.getAttribute("URL") || "";
			["X_HW_CertPassword", "Password", "ConnectionRequestPassword", "STUNPassword"].forEach(attr => {
				const cVal = node.getAttribute(attr);
				if (cVal && cVal.startsWith("$2")) {
					seenCiphertexts.add(cVal);
					decryptedItems.push({
						id: ++itemId,
						category: "SYSTEM",
						categoryLabel: "CWMP / TR-069",
						title: `Management Server (${url || "CWMP"})`,
						field: attr,
						plainValue: decryptHuaweiString(cVal),
						cipherValue: cVal,
						meta: { url }
					});
				}
			});
		});

		// 5. Tokens (<TokenObjInstance>)
		const tokenNodes = xmlDoc.querySelectorAll("TokenObjInstance");
		tokenNodes.forEach(token => {
			const instId = token.getAttribute("InstanceID") || "";
			const tokenVal = token.getAttribute("Token");
			if (tokenVal && tokenVal.startsWith("$2")) {
				seenCiphertexts.add(tokenVal);
				decryptedItems.push({
					id: ++itemId,
					category: "TOKEN",
					categoryLabel: "Token Object",
					title: `Token Instance #${instId}`,
					field: "Token",
					plainValue: decryptHuaweiString(tokenVal),
					cipherValue: tokenVal,
					meta: { instanceId: instId }
				});
			}
		});
	}

	// 6. Universal Regex Scanner (Catches any remaining $2...$ ciphertext anywhere in the XML file)
	const regex = /<([A-Za-z0-9_]+)\b[^>]*\b([A-Za-z0-9_]+)="(\$2[^"]+\$)"/g;
	let match;
	while ((match = regex.exec(xmlString)) !== null) {
		const tagName = match[1];
		const attrName = match[2];
		const cipherVal = match[3];

		if (!seenCiphertexts.has(cipherVal)) {
			seenCiphertexts.add(cipherVal);
			const decrypted = decryptHuaweiString(cipherVal);
			if (decrypted && !isDummyPlaceholderPassword(decrypted, attrName)) {
				let cat = "SYSTEM";
				if (tagName.toLowerCase().includes("user")) cat = "WEB";
				else if (tagName.toLowerCase().includes("wlan") || tagName.toLowerCase().includes("wifi")) cat = "WIFI";
				else if (tagName.toLowerCase().includes("token")) cat = "TOKEN";

				decryptedItems.push({
					id: ++itemId,
					category: cat,
					categoryLabel: tagName,
					title: `${tagName} [${attrName}]`,
					field: attrName,
					plainValue: decrypted,
					cipherValue: cipherVal,
					isWifi: cat === "WIFI",
					meta: { tag: tagName, attr: attrName }
				});
			}
		}
	}

	// Update UI
	renderDecryptionResults();

	// Hide upload dropzone when configuration is active (keeps saved configs section accessible)
	const dropZone = document.getElementById("dropZone");
	if (dropZone) dropZone.style.display = "none";
	const pasteBox = document.getElementById("pasteBox");
	if (pasteBox) pasteBox.style.display = "none";

	// Keep view anchored at the top
	ensureTopViewport();

	// Save to Local Storage History (if enabled)
	if (saveToHistory) {
		saveConfigToStorage(fileName, xmlString, decryptedItems.length);
	}
}

// -------------------------------------------------------------
// UI Rendering & Interactivity
// -------------------------------------------------------------
function renderDecryptionResults() {
	const resultsContainer = document.getElementById("resultsContainer");
	resultsContainer.style.display = "block";

	// Summary Toolbar Meta
	document.getElementById("summaryFileName").textContent = currentFileName;
	const sizeKb = (new Blob([currentXmlText]).size / 1024).toFixed(1);
	document.getElementById("summaryFileSize").textContent = `${sizeKb} KB`;
	document.getElementById("summaryDecryptedCount").textContent = `${decryptedItems.length} credentials decrypted`;

	// Update Category Counts
	const counts = {
		ALL: decryptedItems.length,
		WEB: decryptedItems.filter(i => i.category === "WEB").length,
		WIFI: decryptedItems.filter(i => i.category === "WIFI").length,
		CLI: decryptedItems.filter(i => i.category === "CLI").length,
		SYSTEM: decryptedItems.filter(i => i.category === "SYSTEM").length,
		TOKEN: decryptedItems.filter(i => i.category === "TOKEN").length
	};

	document.getElementById("countAll").textContent = counts.ALL;
	document.getElementById("countWeb").textContent = counts.WEB;
	document.getElementById("countWifi").textContent = counts.WIFI;
	document.getElementById("countCli").textContent = counts.CLI;
	document.getElementById("countSystem").textContent = counts.SYSTEM;
	document.getElementById("countTokens").textContent = counts.TOKEN;

	// Render Highlight Cards
	renderHighlightCards();

	// Render Filtered Table
	renderTableRows();
}

function renderHighlightCards() {
	// 1. Web Users Highlight
	const webUsersContainer = document.getElementById("highlightWebUsers");
	webUsersContainer.innerHTML = "";
	const webItems = decryptedItems.filter(i => i.category === "WEB");

	// Group by username (merging IteratePassword into the same user tile)
	const userGroups = {};
	webItems.forEach(item => {
		let uName = ((item.meta && item.meta.userName) || item.title || "User").replace(/\s*\(IteratePassword\)/i, "").trim();
		if (!userGroups[uName]) userGroups[uName] = [];
		userGroups[uName].push(item);
	});

	// Sort admin accounts first
	const sortedUserNames = Object.keys(userGroups).sort((a, b) => {
		const aIsAdmin = a.toLowerCase().includes("admin");
		const bIsAdmin = b.toLowerCase().includes("admin");
		if (aIsAdmin && !bIsAdmin) return -1;
		if (!aIsAdmin && bIsAdmin) return 1;
		return a.localeCompare(b);
	});

	if (sortedUserNames.length === 0) {
		webUsersContainer.innerHTML = '<p class="cred-label">No web user credentials found.</p>';
	} else {
		sortedUserNames.forEach(uName => {
			const items = userGroups[uName];
			const isFeatured = uName.toLowerCase().includes("admin");
			const userLevel = items[0]?.meta?.userLevel ?? "";
			const roleText = userLevel === "0" ? "Admin (Level 0)" : (userLevel === "1" ? "User (Level 1)" : "Web User");

			let html = `
				<div class="user-highlight-item ${isFeatured ? 'featured' : ''}">
					<div class="user-item-title">
						<span class="username-tag">${escapeHtml(uName)}</span>
						<span class="account-role">${roleText}</span>
					</div>
			`;

			items.forEach(it => {
				const isFactory = it.field.includes("Factory");
				const valueClass = isFactory ? "factory-pass" : (it.isHash ? "hash-val" : "");
				html += `
					<div class="credential-row">
						<span class="cred-label">${escapeHtml(it.field)}:</span>
						<div class="cred-value-wrap">
							<span class="cred-value ${valueClass}" title="${escapeHtml(it.plainValue)}">${escapeHtml(it.plainValue)}</span>
							<button type="button" class="btn-icon-copy" onclick="copyToClipboard('${escapeJsString(it.plainValue)}')" title="Copy to clipboard">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
							</button>
						</div>
					</div>
				`;
			});

			html += `</div>`;
			webUsersContainer.insertAdjacentHTML("beforeend", html);
		});
	}

	// 2. Wi-Fi Highlight
	const wifiContainer = document.getElementById("highlightWifi");
	wifiContainer.innerHTML = "";
	const wifiItems = decryptedItems.filter(i => i.category === "WIFI");

	if (wifiItems.length === 0) {
		wifiContainer.innerHTML = '<p class="cred-label">No Wi-Fi credentials found.</p>';
	} else {
		// Group by SSID / title
		const wifiGroups = {};
		wifiItems.forEach(item => {
			const groupKey = item.title;
			if (!wifiGroups[groupKey]) wifiGroups[groupKey] = [];
			wifiGroups[groupKey].push(item);
		});

		Object.keys(wifiGroups).forEach(groupKey => {
			const items = wifiGroups[groupKey];
			let html = `
				<div class="user-highlight-item">
					<div class="user-item-title">
						<span class="username-tag">${escapeHtml(groupKey)}</span>
					</div>
			`;
			items.forEach(it => {
				const isPsk = it.field.includes("PreSharedKey") || (it.isWifi && !it.field.includes("WPS"));
				html += `
					<div class="credential-row">
						<span class="cred-label">${escapeHtml(it.field)}:</span>
						<div class="cred-value-wrap">
							${isPsk ? `
								<span class="cred-value wifi-pass masked" id="wifi_val_${it.id}" data-plain="${escapeHtml(it.plainValue)}" data-masked="true">••••••••••••</span>
								<button type="button" class="btn-icon-unveil" onclick="togglePasswordVisibility('wifi_val_${it.id}', this)" title="Show / Hide password">
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
								</button>
							` : `
								<span class="cred-value wifi-pass" title="${escapeHtml(it.plainValue)}">${escapeHtml(it.plainValue)}</span>
							`}
							<button type="button" class="btn-icon-copy" onclick="copyToClipboard('${escapeJsString(it.plainValue)}')" title="Copy password">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
							</button>
						</div>
					</div>
				`;
			});
			html += `</div>`;
			wifiContainer.insertAdjacentHTML("beforeend", html);
		});
	}

	// 3. CLI Accounts Highlight
	const cliContainer = document.getElementById("highlightCli");
	cliContainer.innerHTML = "";
	const cliItems = decryptedItems.filter(i => i.category === "CLI");
	if (cliItems.length === 0) {
		cliContainer.innerHTML = '<p class="cred-label">No CLI user credentials found.</p>';
	} else {
		cliItems.forEach(it => {
			const html = `
				<div class="user-highlight-item">
					<div class="user-item-title">
						<span class="username-tag">${escapeHtml(it.title)}</span>
						<span class="account-role">${escapeHtml(it.meta?.access || "CLI")}</span>
					</div>
					<div class="credential-row">
						<span class="cred-label">${escapeHtml(it.field)}:</span>
						<div class="cred-value-wrap">
							<span class="cred-value ${it.isHash ? 'hash-val' : ''}" title="${escapeHtml(it.plainValue)}">${escapeHtml(it.plainValue)}</span>
							<button type="button" class="btn-icon-copy" onclick="copyToClipboard('${escapeJsString(it.plainValue)}')" title="Copy to clipboard">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
							</button>
						</div>
					</div>
				</div>
			`;
			cliContainer.insertAdjacentHTML("beforeend", html);
		});
	}

	// 4. System & CWMP Highlight
	const sysContainer = document.getElementById("highlightSystem");
	sysContainer.innerHTML = "";
	const sysItems = decryptedItems.filter(i => i.category === "SYSTEM");
	if (sysItems.length === 0) {
		sysContainer.innerHTML = '<p class="cred-label">No system or SSL credentials found.</p>';
	} else {
		sysItems.slice(0, 4).forEach(it => {
			const html = `
				<div class="user-highlight-item">
					<div class="user-item-title">
						<span class="username-tag">${escapeHtml(it.title)}</span>
					</div>
					<div class="credential-row">
						<span class="cred-label">${escapeHtml(it.field)}:</span>
						<div class="cred-value-wrap">
							<span class="cred-value ${it.isHash ? 'hash-val' : ''}" title="${escapeHtml(it.plainValue)}">${escapeHtml(it.plainValue)}</span>
							<button type="button" class="btn-icon-copy" onclick="copyToClipboard('${escapeJsString(it.plainValue)}')" title="Copy to clipboard">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
							</button>
						</div>
					</div>
				</div>
			`;
			sysContainer.insertAdjacentHTML("beforeend", html);
		});
	}
}

function renderTableRows() {
	const tableBody = document.getElementById("credentialsTableBody");
	const noResultsMsg = document.getElementById("noResultsMessage");
	tableBody.innerHTML = "";

	const filtered = decryptedItems.filter(item => {
		// Category filter
		if (activeCategory !== "ALL" && item.category !== activeCategory) {
			return false;
		}
		// Search query
		if (searchQuery) {
			const q = searchQuery.toLowerCase();
			const matchTitle = item.title.toLowerCase().includes(q);
			const matchField = item.field.toLowerCase().includes(q);
			const matchPlain = item.plainValue.toLowerCase().includes(q);
			const matchCategory = item.categoryLabel.toLowerCase().includes(q);
			return matchTitle || matchField || matchPlain || matchCategory;
		}
		return true;
	});

	if (filtered.length === 0) {
		noResultsMsg.style.display = "block";
		return;
	} else {
		noResultsMsg.style.display = "none";
	}

	filtered.forEach(it => {
		let badgeClass = "badge-info";
		if (it.category === "WEB") badgeClass = "badge-success";
		else if (it.category === "CLI") badgeClass = "badge-purple";
		else if (it.category === "SYSTEM") badgeClass = "badge-warning";
		else if (it.category === "TOKEN") badgeClass = "badge-purple";

		const isWifiPsk = it.isWifi && it.field.includes("PreSharedKey");
		const rowHtml = `
			<tr>
				<td>
					<span class="badge ${badgeClass}">${escapeHtml(it.categoryLabel || it.category)}</span>
				</td>
				<td>
					<div class="table-field-title">${escapeHtml(it.title)}</div>
					<div class="table-field-meta">${escapeHtml(it.field)}</div>
				</td>
				<td>
					<div class="code-cell">
						${isWifiPsk ? `
							<span class="code-cell-text wifi-pass masked" id="tbl_val_${it.id}" data-plain="${escapeHtml(it.plainValue)}" data-masked="true">
								••••••••••••
							</span>
						` : `
							<span class="code-cell-text ${it.isFactory ? 'factory-pass' : (it.isWifi ? 'wifi-pass' : (it.isHash ? 'hash-val' : ''))}" title="${escapeHtml(it.plainValue)}">
								${escapeHtml(it.plainValue)}
							</span>
						`}
						<div class="code-cell-actions">
							${isWifiPsk ? `
								<button type="button" class="btn-icon-unveil" onclick="togglePasswordVisibility('tbl_val_${it.id}', this)" title="Show / Hide password">
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
								</button>
							` : ''}
							<button type="button" class="btn-icon-copy" onclick="copyToClipboard('${escapeJsString(it.plainValue)}')" title="Copy plaintext">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
							</button>
						</div>
					</div>
				</td>
			</tr>
		`;
		tableBody.insertAdjacentHTML("beforeend", rowHtml);
	});
}

// -------------------------------------------------------------
// Export & Action Handlers
// -------------------------------------------------------------
function downloadDecryptedXmlFile() {
	if (!currentXmlText) {
		showToast("No XML configuration loaded.", "warning");
		return;
	}

	// Replace every ciphertext in the XML with its decrypted string
	let modifiedXml = currentXmlText;
	const regex = /(\$2[^"<\s]+\$)/g;
	modifiedXml = modifiedXml.replace(regex, (match) => {
		const dec = decryptHuaweiString(match);
		return dec ? dec : match;
	});

	const blob = new Blob([modifiedXml], { type: "application/xml;charset=utf-8" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = currentFileName.replace(/\.xml$/i, "") + "_decrypted.xml";
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
	showToast("Decrypted XML downloaded!");
}

function exportCredentialsJson() {
	if (!decryptedItems || decryptedItems.length === 0) {
		showToast("No decrypted credentials available.", "warning");
		return;
	}

	const exportData = {
		sourceFile: currentFileName,
		timestamp: new Date().toISOString(),
		totalCount: decryptedItems.length,
		credentials: decryptedItems.map(it => ({
			category: it.category,
			target: it.title,
			field: it.field,
			plaintext: it.plainValue,
			ciphertext: it.cipherValue,
			meta: it.meta || {}
		}))
	};

	const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json;charset=utf-8" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = currentFileName.replace(/\.xml$/i, "") + "_credentials.json";
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
	showToast("Credentials JSON exported!");
}

function copyAllPasswords() {
	if (!decryptedItems || decryptedItems.length === 0) {
		showToast("No credentials to copy.", "warning");
		return;
	}

	let text = `=== Huawei Router Decrypted Passwords (${currentFileName}) ===\n\n`;
	decryptedItems.forEach(it => {
		text += `[${it.categoryLabel || it.category}] ${it.title} - ${it.field}: ${it.plainValue}\n`;
	});

	copyToClipboard(text, "All passwords copied to clipboard!");
}

function copyToClipboard(text, customMessage = "Copied to clipboard!") {
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(() => {
			showToast(customMessage);
		}).catch(err => {
			fallbackCopy(text, customMessage);
		});
	} else {
		fallbackCopy(text, customMessage);
	}
}

function fallbackCopy(text, customMessage) {
	const textarea = document.createElement("textarea");
	textarea.value = text;
	textarea.style.position = "fixed";
	textarea.style.opacity = "0";
	document.body.appendChild(textarea);
	textarea.focus();
	textarea.select();
	try {
		document.execCommand("copy");
		showToast(customMessage);
	} catch (e) {
		showToast("Failed to copy", "warning");
	}
	document.body.removeChild(textarea);
}

function showToast(message, type = "success") {
	const toast = document.getElementById("toastNotification");
	if (!toast) return;
	toast.textContent = message;
	toast.classList.add("show");
	setTimeout(() => {
		toast.classList.remove("show");
	}, 2800);
}

// -------------------------------------------------------------
// Helper Utilities
// -------------------------------------------------------------
function escapeHtml(str) {
	if (!str) return "";
	return String(str)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

function escapeJsString(str) {
	if (!str) return "";
	return String(str)
		.replace(/\\/g, "\\\\")
		.replace(/'/g, "\\'")
		.replace(/"/g, '\\"')
		.replace(/\n/g, "\\n")
		.replace(/\r/g, "\\r");
}

// Prevent browser from auto-scrolling to bottom on dynamic content injection
if ('scrollRestoration' in history) {
	history.scrollRestoration = 'manual';
}

function ensureTopViewport() {
	try {
		if (document.activeElement && document.activeElement.blur && document.activeElement !== document.body) {
			document.activeElement.blur();
		}
	} catch (_) {}
	window.scrollTo(0, 0);
	requestAnimationFrame(() => {
		window.scrollTo(0, 0);
		setTimeout(() => {
			window.scrollTo(0, 0);
		}, 50);
	});
}

// -------------------------------------------------------------
// Client-Side Local Storage & History Management
// -------------------------------------------------------------
const STORAGE_CONFIGS_KEY = "hw_util_saved_configs_v1";
const STORAGE_LAST_ACTIVE_KEY = "hw_util_last_active_id";
const STORAGE_REMEMBER_KEY = "hw_util_remember_configs";
const MAX_HISTORY_CONFIGS = 6;

function isRememberConfigsEnabled() {
	try {
		const stored = localStorage.getItem(STORAGE_REMEMBER_KEY);
		return stored === null ? true : stored === "true";
	} catch (e) {
		return false;
	}
}

function setRememberConfigsEnabled(enabled) {
	try {
		localStorage.setItem(STORAGE_REMEMBER_KEY, enabled ? "true" : "false");
	} catch (e) {
		console.warn("Could not save storage preference:", e);
	}
}

function getSavedConfigs() {
	try {
		const raw = localStorage.getItem(STORAGE_CONFIGS_KEY);
		return raw ? JSON.parse(raw) : [];
	} catch (e) {
		console.warn("Could not read saved configs from localStorage:", e);
		return [];
	}
}

function saveConfigToStorage(fileName, xmlText, decryptedCount) {
	if (!isRememberConfigsEnabled() || !xmlText) return;
	try {
		let configs = getSavedConfigs();
		// Remove existing entry with same fileName or identical XML content to avoid redundancy
		configs = configs.filter(c => c.fileName !== fileName && c.xmlContent !== xmlText);

		const sizeKb = (new Blob([xmlText]).size / 1024).toFixed(1) + " KB";
		const now = new Date();
		const savedAt = now.toLocaleDateString() + " " + now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

		const newEntry = {
			id: "cfg_" + Date.now() + "_" + Math.random().toString(36).substr(2, 4),
			fileName: fileName || "hw_ctree.xml",
			fileSize: sizeKb,
			savedAt: savedAt,
			xmlContent: xmlText,
			decryptedCount: decryptedCount || 0
		};

		configs.unshift(newEntry);
		if (configs.length > MAX_HISTORY_CONFIGS) {
			configs = configs.slice(0, MAX_HISTORY_CONFIGS);
		}

		// Save with quota handling fallback
		let saved = false;
		while (!saved && configs.length > 0) {
			try {
				localStorage.setItem(STORAGE_CONFIGS_KEY, JSON.stringify(configs));
				localStorage.setItem(STORAGE_LAST_ACTIVE_KEY, newEntry.id);
				saved = true;
			} catch (e) {
				// Quota exceeded: trim oldest
				if (configs.length > 1) {
					configs.pop();
				} else {
					console.warn("LocalStorage full, cannot save config:", e);
					break;
				}
			}
		}

		renderRecentConfigsUI();
	} catch (err) {
		console.warn("Failed saving to localStorage:", err);
	}
}

function deleteSavedConfig(id) {
	try {
		let configs = getSavedConfigs();
		configs = configs.filter(c => c.id !== id);
		localStorage.setItem(STORAGE_CONFIGS_KEY, JSON.stringify(configs));
		
		const activeId = localStorage.getItem(STORAGE_LAST_ACTIVE_KEY);
		if (activeId === id) {
			localStorage.removeItem(STORAGE_LAST_ACTIVE_KEY);
		}
		
		renderRecentConfigsUI();
		showToast("Removed file from browser storage.");
	} catch (e) {
		console.warn("Could not delete saved config:", e);
	}
}

function clearAllSavedConfigs() {
	if (!confirm("Are you sure you want to clear all stored router configuration files from this browser?")) {
		return;
	}
	try {
		localStorage.removeItem(STORAGE_CONFIGS_KEY);
		localStorage.removeItem(STORAGE_LAST_ACTIVE_KEY);
		renderRecentConfigsUI();
		showToast("All saved configurations cleared from browser storage.");
	} catch (e) {
		console.warn("Could not clear storage:", e);
	}
}

function loadConfigById(id) {
	const configs = getSavedConfigs();
	const target = configs.find(c => c.id === id);
	if (target && target.xmlContent) {
		try {
			localStorage.setItem(STORAGE_LAST_ACTIVE_KEY, id);
		} catch (_) {}
		parseAndDecryptXml(target.xmlContent, target.fileName, false);
		renderRecentConfigsUI();
		showToast(`Loaded "${target.fileName}" from browser storage`);
	} else {
		showToast("Could not load configuration.", "warning");
	}
}

function loadLastActiveConfigOnStartup() {
	if (!isRememberConfigsEnabled()) return;
	const configs = getSavedConfigs();
	if (configs.length === 0) return;

	const activeId = localStorage.getItem(STORAGE_LAST_ACTIVE_KEY);
	const target = configs.find(c => c.id === activeId) || configs[0];
	if (target && target.xmlContent) {
		parseAndDecryptXml(target.xmlContent, target.fileName, false);
		renderRecentConfigsUI();
	}
}

function renderRecentConfigsUI() {
	const section = document.getElementById("recentConfigsSection");
	const list = document.getElementById("savedConfigsList");
	const countElem = document.getElementById("savedConfigsCount");
	const chkRemember = document.getElementById("chkRememberConfigs");

	if (chkRemember) {
		chkRemember.checked = isRememberConfigsEnabled();
	}

	if (!section || !list) return;

	const configs = getSavedConfigs();
	if (countElem) countElem.textContent = configs.length;

	if (configs.length === 0) {
		section.style.display = "none";
		list.innerHTML = "";
		return;
	}

	section.style.display = "block";
	const activeId = localStorage.getItem(STORAGE_LAST_ACTIVE_KEY);

	list.innerHTML = configs.map(cfg => {
		const isActive = cfg.id === activeId || (cfg.fileName === currentFileName && currentXmlText === cfg.xmlContent);
		return `
			<div class="recent-config-card ${isActive ? 'active-config' : ''}" data-id="${cfg.id}">
				<div class="recent-card-top">
					<div class="recent-file-info">
						<svg class="recent-file-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
						<span class="recent-file-name" title="${escapeHtml(cfg.fileName)}">${escapeHtml(cfg.fileName)}</span>
					</div>
					<button type="button" class="btn-icon-danger btn-delete-config" data-id="${cfg.id}" title="Remove this file from saved storage">
						<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
					</button>
				</div>
				<div class="recent-card-meta">
					<span class="recent-pill">${escapeHtml(cfg.fileSize)}</span>
					<span class="recent-pill recent-pill-count">${cfg.decryptedCount} items</span>
					<span class="recent-pill">${escapeHtml(cfg.savedAt)}</span>
				</div>
				<div class="recent-card-actions">
					<button type="button" class="btn btn-sm ${isActive ? 'btn-outline' : 'btn-primary'} btn-load-config" data-id="${cfg.id}">
						${isActive ? '✓ Currently Loaded' : 'Restore & View'}
					</button>
				</div>
			</div>
		`;
	}).join("");

	// Attach click listeners
	list.querySelectorAll(".btn-load-config").forEach(btn => {
		btn.addEventListener("click", (e) => {
			e.stopPropagation();
			const id = btn.getAttribute("data-id");
			if (id) loadConfigById(id);
		});
	});

	list.querySelectorAll(".btn-delete-config").forEach(btn => {
		btn.addEventListener("click", (e) => {
			e.stopPropagation();
			const id = btn.getAttribute("data-id");
			if (id) deleteSavedConfig(id);
		});
	});
}

// -------------------------------------------------------------
// Drag & Drop / File Loading Setup
// -------------------------------------------------------------
function setupFileHandlers() {
	const dropZone = document.getElementById("dropZone");
	const fileInput = document.getElementById("xmlFileInput");
	const btnBrowse = document.getElementById("btnBrowseFile");
	const btnTogglePaste = document.getElementById("btnTogglePaste");
	const pasteBox = document.getElementById("pasteBox");
	const btnParsePasted = document.getElementById("btnParsePasted");
	const btnCancelPaste = document.getElementById("btnCancelPaste");
	const pasteTextarea = document.getElementById("pasteTextarea");

	if (btnBrowse && fileInput) {
		btnBrowse.addEventListener("click", (e) => {
			e.stopPropagation();
			fileInput.click();
		});
	}

	if (dropZone) {
		dropZone.addEventListener("click", () => {
			if (fileInput) fileInput.click();
		});

		dropZone.addEventListener("dragover", (e) => {
			e.preventDefault();
			dropZone.classList.add("dragover");
		});

		dropZone.addEventListener("dragleave", () => {
			dropZone.classList.remove("dragover");
		});

		dropZone.addEventListener("drop", (e) => {
			e.preventDefault();
			dropZone.classList.remove("dragover");
			if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
				const file = e.dataTransfer.files[0];
				loadFile(file);
			}
		});
	}

	if (fileInput) {
		fileInput.addEventListener("change", (e) => {
			if (e.target.files && e.target.files.length > 0) {
				const file = e.target.files[0];
				loadFile(file);
			}
		});
	}


	if (btnTogglePaste && pasteBox) {
		btnTogglePaste.addEventListener("click", (e) => {
			e.stopPropagation();
			pasteBox.style.display = pasteBox.style.display === "none" ? "block" : "none";
		});
	}

	if (btnCancelPaste && pasteBox) {
		btnCancelPaste.addEventListener("click", () => {
			pasteBox.style.display = "none";
		});
	}

	if (btnParsePasted && pasteTextarea) {
		btnParsePasted.addEventListener("click", () => {
			const text = pasteTextarea.value.trim();
			if (!text) {
				showToast("Please paste XML content first.", "warning");
				return;
			}
			parseAndDecryptXml(text, "pasted_config.xml");
			pasteBox.style.display = "none";
			showToast("Pasted XML decrypted successfully!");
		});
	}

	// Action buttons in toolbar
	const btnOpenNewConfig = document.getElementById("btnOpenNewConfig");
	if (btnOpenNewConfig) {
		btnOpenNewConfig.addEventListener("click", () => {
			const dropZone = document.getElementById("dropZone");
			if (dropZone) {
				const isHidden = dropZone.style.display === "none";
				dropZone.style.display = isHidden ? "block" : "none";
				if (isHidden) {
					dropZone.scrollIntoView({ behavior: "smooth", block: "start" });
				}
			}
		});
	}

	const btnCopyAll = document.getElementById("btnCopyAll");
	if (btnCopyAll) btnCopyAll.addEventListener("click", copyAllPasswords);

	const btnExportJson = document.getElementById("btnExportJson");
	if (btnExportJson) btnExportJson.addEventListener("click", exportCredentialsJson);

	const btnDownloadXml = document.getElementById("btnDownloadDecryptedXml");
	if (btnDownloadXml) btnDownloadXml.addEventListener("click", downloadDecryptedXmlFile);

	// Search & Category Filters
	const searchInput = document.getElementById("credentialSearchInput");
	const btnClearSearch = document.getElementById("btnClearSearch");
	if (searchInput) {
		searchInput.addEventListener("input", (e) => {
			searchQuery = e.target.value.trim();
			if (btnClearSearch) {
				btnClearSearch.style.display = searchQuery ? "block" : "none";
			}
			renderTableRows();
		});
	}

	if (btnClearSearch && searchInput) {
		btnClearSearch.addEventListener("click", () => {
			searchInput.value = "";
			searchQuery = "";
			btnClearSearch.style.display = "none";
			renderTableRows();
		});
	}

	const pillBtns = document.querySelectorAll(".pill-btn");
	pillBtns.forEach(btn => {
		btn.addEventListener("click", () => {
			pillBtns.forEach(b => b.classList.remove("active"));
			btn.classList.add("active");
			activeCategory = btn.getAttribute("data-category") || "ALL";
			renderTableRows();
		});
	});

	// Storage controls
	const btnClearSaved = document.getElementById("btnClearSavedConfigs");
	if (btnClearSaved) {
		btnClearSaved.addEventListener("click", clearAllSavedConfigs);
	}

	const chkRemember = document.getElementById("chkRememberConfigs");
	if (chkRemember) {
		chkRemember.addEventListener("change", (e) => {
			setRememberConfigsEnabled(e.target.checked);
			if (!e.target.checked) {
				showToast("Auto-saving disabled on this device.", "info");
			} else {
				showToast("Auto-saving enabled for uploaded configurations.");
			}
		});
	}
}

function loadFile(file) {
	const reader = new FileReader();
	reader.onload = (e) => {
		const text = e.target.result;
		parseAndDecryptXml(text, file.name);
		showToast(`File "${file.name}" decrypted successfully!`);
	};
	reader.readAsText(file);
}

// -------------------------------------------------------------
// Existing Password Generator & Cipher Worker Routines
// -------------------------------------------------------------
function GetRandomSalt() {
	var randomBytes = new Uint8Array(12);
	for (let i = 0; i < randomBytes.length; i++) {
		randomBytes[i] = (Math.random() * 255) >> 0;
	}
	return randomBytes.reduce((previous, currentValue) => { return previous + currentValue.toString(16); }, "");
}

function GeneratePasswordOnWorker(password, salt, mode) {
	myWorker.postMessage({
		functionCall: GENERATE_PASSWORD,
		args: { password, salt, mode }
	});
}

function EncryptPasswordOnWorker(password, field) {
	myWorker.postMessage({
		functionCall: ENCRYPT_DATA,
		args: { password, field }
	});
}

function DecryptPasswordOnWorker(password, field) {
	myWorker.postMessage({
		functionCall: DECRYPT_DATA,
		args: { password, field }
	});
}

function OnPasswordChange() {
	if (!sendToWorker) return;
	let mode = document.getElementById("EncryptionMode").value * 1;
	let saltField = document.getElementById("SaltField");
	let randomize = document.getElementById("SaltRandomizeField").checked;
	if (randomize === true && mode === ENCRYPTION_MODE_PBKDF2) {
		saltField.value = GetRandomSalt();
	}
	let salt = saltField.value;
	let password = document.getElementById("PasswordField").value;
	GeneratePasswordOnWorker(password, salt, mode);
}

function OnRandomizeFieldChange() {
	let mode = document.getElementById("EncryptionMode").value * 1;
	if (mode !== ENCRYPTION_MODE_PBKDF2) return;
	let randomizeField = document.getElementById("SaltRandomizeField");
	let salt = document.getElementById("SaltField");
	if (randomizeField.checked === true) {
		salt.classList.add("no-input");
		salt.disabled = true;
		OnPasswordChange();
	} else {
		salt.classList.remove("no-input");
		salt.disabled = false;
	}
}

function EncryptionModeChange() {
	let mode = document.getElementById("EncryptionMode").value * 1;
	let salt = document.getElementById("SaltField");
	let randomizeField = document.getElementById("SaltRandomizeField");
	switch (mode) {
		case ENCRYPTION_MODE_MD5:
		case ENCRYPTION_MODE_SHA2_MD5:
			randomizeField.disabled = true;
			salt.disabled = true;
			salt.classList.add('disabled');
			salt.classList.remove("no-input");
			salt.value = "";
			break;
		case ENCRYPTION_MODE_PBKDF2:
			salt.disabled = false;
			salt.classList.remove('disabled');
			randomizeField.disabled = false;
			if (randomizeField.checked === true) {
				salt.classList.add("no-input");
				salt.disabled = true;
				if (salt.value === "")
					salt.value = GetRandomSalt();
			}
			break;
	}
	GeneratePasswordOnWorker(document.getElementById("PasswordField").value, salt.value, mode);
}

function OnEncryptResultClick() {
	let encryptResultField = document.getElementById("EncryptResultField");
	let resultField = document.getElementById("ResultField");
	let mode = document.getElementById("EncryptionMode").value * 1;
	let salt = document.getElementById("SaltField");
	if (encryptResultField.checked === true) {
		EncryptPasswordOnWorker(resultField.value, "ResultField");
	} else {
		GeneratePasswordOnWorker(document.getElementById("PasswordField").value, salt.value, mode);
	}
}

function OnCipherInputChange() {
	const CipherInputField = document.getElementById("CipherInputField").value;
	const CipherFunctionField = document.getElementById("CipherFunctionField").value - 1;
	if (CipherFunctionField === DECRYPT_DATA) {
		if (typeof he !== 'undefined' && he.decode) {
			DecryptPasswordOnWorker(he.decode(CipherInputField.trim()), "CipherResultField");
		} else {
			DecryptPasswordOnWorker(CipherInputField.trim(), "CipherResultField");
		}
	} else {
		EncryptPasswordOnWorker(CipherInputField, "CipherResultField");
	}
}

myWorker.addEventListener('message', (e) => {
	let encryptResultField = document.getElementById("EncryptResultField");
	let resultField = document.getElementById("ResultField");
	switch (e.data.functionCall) {
		case GENERATE_PASSWORD:
			if (encryptResultField && encryptResultField.checked === true) {
				EncryptPasswordOnWorker(e.data.return, "ResultField");
			} else if (resultField) {
				resultField.value = e.data.return;
			}
			break;
		case DECRYPT_DATA:
		case ENCRYPT_DATA:
			let field = document.getElementById(e.data.field);
			if (field) field.value = e.data.return;
			break;
	}
});

// -------------------------------------------------------------
// Navigation & Initialization
// -------------------------------------------------------------
const pages = ["xmlparser", "passgen", "cipher", "home"];

function popStateEvent() {
	let target = document.location.hash.substr(1);
	if (target === "" || !pages.includes(target)) {
		target = "xmlparser";
	}

	pages.forEach(page => {
		const elem = document.getElementById(page);
		const link = document.getElementById(page + "link");
		if (elem) {
			if (page === target) {
				elem.style.display = "block";
				if (link) link.classList.add("active-page");
			} else {
				elem.style.display = "none";
				if (link) link.classList.remove("active-page");
			}
		}
	});
}

// -------------------------------------------------------------
// Legal Disclaimer Modal Handling
// -------------------------------------------------------------
function openDisclaimerModal() {
	const modal = document.getElementById("disclaimerModal");
	if (modal) {
		modal.style.display = "flex";
		document.body.style.overflow = "hidden";
	}
}

function closeDisclaimerModal() {
	const modal = document.getElementById("disclaimerModal");
	if (modal) {
		modal.style.display = "none";
		document.body.style.overflow = "";
	}
}

function setupDisclaimerModal() {
	const openBtn = document.getElementById("btnOpenDisclaimerModal");
	const closeBtn = document.getElementById("btnCloseDisclaimerModal");
	const ackBtn = document.getElementById("btnAcknowledgeDisclaimer");
	const modal = document.getElementById("disclaimerModal");

	if (openBtn) openBtn.addEventListener("click", openDisclaimerModal);
	if (closeBtn) closeBtn.addEventListener("click", closeDisclaimerModal);
	if (ackBtn) ackBtn.addEventListener("click", closeDisclaimerModal);

	if (modal) {
		modal.addEventListener("click", (e) => {
			if (e.target === modal) {
				closeDisclaimerModal();
			}
		});
	}

	window.addEventListener("keydown", (e) => {
		if (e.key === "Escape" && modal && modal.style.display === "flex") {
			closeDisclaimerModal();
		}
	});
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
	setupFileHandlers();
	setupDisclaimerModal();
	renderRecentConfigsUI();
	loadLastActiveConfigOnStartup();
	EncryptionModeChange();
	OnRandomizeFieldChange();
	sendToWorker = true;
	GeneratePasswordOnWorker(
		document.getElementById("PasswordField")?.value || "",
		document.getElementById("SaltField")?.value || "",
		(document.getElementById("EncryptionMode")?.value || 1) * 1
	);
	OnCipherInputChange();
	popStateEvent();
});

window.addEventListener('popstate', popStateEvent);