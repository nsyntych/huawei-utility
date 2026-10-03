const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const context = {
	CryptoJS: require(path.join(root, "js/vendor/crypto-js.min.js")),
	Uint8Array,
	Uint32Array,
	console,
	postMessage() {},
	importScripts() {},
	crypto: {
		getRandomValues(bytes) {
			for (let index = 0; index < bytes.length; index++) bytes[index] = index;
			return bytes;
		}
	}
};

vm.createContext(context);
vm.runInContext(
	[
		"js/constants.js",
		"js/random.js",
		"js/worker.js"
	].map(file => fs.readFileSync(path.join(root, file), "utf8")).join("\n"),
	context
);

const password = "owner-test-password";
const parentSalt = "00112233445566778899aabb";
const iterateSalt = "ffeeddccbbaa998877665544";

const md5 = crypto.createHash("md5").update(password).digest("hex");
assert.equal(context.GeneratePassword(password, "", 1), md5);
assert.equal(
	context.GeneratePassword(password, "", 2),
	crypto.createHash("sha256").update(md5).digest("hex")
);

assert.equal(
	context.GeneratePassword(password, parentSalt, 3),
	"c26ba8ec92cbdd41b6b98730d5e94542acd0774b1ffdbf2a26669e90d5a7ff69",
	"PassMode 3 parent verifier must retain the 5,000-round default"
);
assert.equal(
	context.GeneratePassword(password, iterateSalt, 3, 10000),
	"6022bea2bdc9d5dbc06f54da7bdb9627b7fb5e4d459e64698542ef61fa81ccca",
	"X_HW_IteratePassword must honor its 10,000-round IterateCount"
);

const independentlyDerived = crypto.pbkdf2Sync(password, iterateSalt, 10000, 32, "sha256").toString("hex");
assert.equal(context.GeneratePassword(password, iterateSalt, 3, 10000), independentlyDerived);
assert.throws(() => context.GeneratePassword(password, parentSalt, 3, 0), /positive integer/);
assert.throws(() => context.GeneratePassword(password, parentSalt, 3, 1.5), /positive integer/);

let workerReply;
context.postMessage = message => { workerReply = message; };
context.onmessage({
	data: {
		functionCall: 2,
		args: {password, salt: iterateSalt, mode: 3, iterations: 10000}
	}
});
assert.equal(workerReply.return, independentlyDerived);

assert.deepEqual(Array.from(context.GetRandomByteArray(4)), [0, 1, 2, 3]);
assert.equal(context.GetRandomHex(12), "000102030405060708090a0b");
assert.equal(context.GetRandomHex(12).length, 24);

console.log("password-generator tests: OK");
