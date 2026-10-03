function GetRandomByteArray(size) {
	if (!Number.isSafeInteger(size) || size < 0) {
		throw new RangeError("Random byte-array size must be a non-negative integer");
	}
	const randomBytes = new Uint8Array(size);
	crypto.getRandomValues(randomBytes);
	return randomBytes;
}

function GetRandomHex(size) {
	return Array.from(
		GetRandomByteArray(size),
		byte => byte.toString(16).padStart(2, "0")
	).join("");
}
