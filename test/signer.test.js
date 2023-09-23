// Copyright 2011 Joyent, Inc.  All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const sshpk = require("sshpk");

const test = require("tap").test;
const uuid = require("uuid").v4;

const httpSignature = require("../lib/index");

///--- Globals

let hmacKey = null;
let httpOptions = null;
let rsaPrivate = null;
let rsaPrivateEncrypted = null;
let dsaPrivate = null;
let ecdsaPrivate = null;
let ed25519Private = null;
let signOptions = null;
let server = null;
let socket = null;

///--- Tests

test("setup", function (t) {
	rsaPrivate = fs.readFileSync(`${__dirname}/rsa_private.pem`, "ascii");
	rsaPrivateEncrypted = fs.readFileSync(
		`${__dirname}/rsa_private_encrypted.pem`,
		"ascii",
	);
	dsaPrivate = fs.readFileSync(`${__dirname}/dsa_private.pem`, "ascii");
	ecdsaPrivate = fs.readFileSync(`${__dirname}/ecdsa_private.pem`, "ascii");

	{
		const { privateKey } = crypto.generateKeyPairSync("ed25519", {
			publicKeyEncoding: {
				type: "spki",
				format: "pem",
			},
			privateKeyEncoding: {
				type: "pkcs8",
				format: "pem",
			},
		});

		ed25519Private = privateKey;
	}

	t.ok(rsaPrivate);
	t.ok(rsaPrivateEncrypted);
	t.ok(dsaPrivate);
	t.ok(ecdsaPrivate);
	t.ok(ed25519Private);

	socket = `/tmp/.${uuid()}`;

	server = http.createServer(function (req, res) {
		res.writeHead(200);
		res.end();
	});

	server.listen(socket, function () {
		hmacKey = uuid();
		httpOptions = {
			socketPath: socket,
			path: "/",
			method: "GET",
			headers: {},
		};

		signOptions = {
			key: rsaPrivate,
			keyId: "unitTest",
		};

		t.end();
	});
});

test("defaults", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	req._stringToSign = null;
	t.ok(httpSignature.sign(req, signOptions));
	const authz = req.getHeader("Authorization");
	t.ok(authz);

	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*$/));

	const key = sshpk.parsePrivateKey(rsaPrivate);
	const sig = key.createSign().update(req._stringToSign).sign();
	t.ok(authz.indexOf(sig.toString()) !== -1);

	console.log(`> ${authz}`);
	req.end();
});

test("with custom authorizationHeaderName", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	req._stringToSign = null;
	const opts = Object.create(signOptions);
	opts.authorizationHeaderName = "x-auths";
	t.ok(httpSignature.sign(req, opts));
	const authz = req.getHeader("x-auths");
	t.ok(authz);

	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*$/));

	const key = sshpk.parsePrivateKey(rsaPrivate);
	const sig = key.createSign().update(req._stringToSign).sign();
	t.ok(authz.indexOf(sig.toString()) !== -1);

	console.log(`> ${authz}`);
	req.end();
});

test("request line strict unspecified", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "request-line"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\nGET \/ HTTP\/1.1$/));

	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("request line strict false", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "request-line"],
		strict: false,
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.ok(!req.hasOwnProperty("_stringToSign"));
	t.ok(req._stringToSign === undefined);
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("request line strict true", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "request-line"],
		strict: true,
	};

	t.throws(function () {
		httpSignature.sign(req, opts);
	});
	req.end();
});

test("request target", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "(request-target)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(request-target\): get \/$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("keyid", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "(keyid)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(keyid\): unit$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("signing algorithm", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		algorithm: "rsa-sha256",
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "(algorithm)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof opts.algorithm, "string");
	t.equal(opts.algorithm, "rsa-sha256");
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(algorithm\): [^\n]*$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("signing with unspecified algorithm", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "(algorithm)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof opts.algorithm, "string");
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(algorithm\): [^\n]*$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("hide algorithm (unspecified algorithm)", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "(algorithm)"],
		hideAlgorithm: true,
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof opts.algorithm, "string");
	t.equal(opts.algorithm, "hs2019");
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(algorithm\): [^\n]*$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("signing opaque param", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		opaque: "opaque",
		headers: ["date", "(opaque)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof opts.algorithm, "string");
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(opaque\): opaque$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("signing with key protected with passphrase", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivateEncrypted,
		keyPassphrase: "123",
		headers: ["date", "(algorithm)"],
	};

	req._stringToSign = null;
	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	t.equal(typeof opts.algorithm, "string");
	t.equal(typeof req._stringToSign, "string");
	t.ok(req._stringToSign.match(/^date: [^\n]*\n\(algorithm\): [^\n]*$/));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("request-target with dsa key", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: dsaPrivate,
		headers: ["date", "(request-target)"],
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("request-target with ecdsa key", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: ecdsaPrivate,
		headers: ["date", "(request-target)"],
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("hmac", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: uuid(),
		algorithm: "hmac-sha1",
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("createSigner with RSA key", function (t) {
	const s = httpSignature.createSigner({
		keyId: "foo",
		key: rsaPrivate,
		algorithm: "rsa-sha1",
	});
	s.writeTarget("get", "/");
	const date = s.writeDateHeader();
	s.sign(function (err, authz) {
		t.error(err);
		console.log(`> ${authz}`);
		const req = http.request(httpOptions, function (res) {
			t.end();
		});
		req.setHeader("date", date);
		req.setHeader("authorization", authz);
		req.end();
	});
});

test("createSigner with RSA key, auto algo", function (t) {
	const s = httpSignature.createSigner({
		keyId: "foo",
		key: rsaPrivate,
	});
	s.writeTarget("get", "/");
	const date = s.writeDateHeader();
	s.sign(function (err, authz) {
		t.error(err);
		const req = http.request(httpOptions, function (res) {
			t.end();
		});
		req.setHeader("date", date);
		req.setHeader("authorization", authz);
		req.end();
	});
});

test("createSigner with RSA key, auto algo, passphrase", function (t) {
	const s = httpSignature.createSigner({
		keyId: "foo",
		key: rsaPrivateEncrypted,
		keyPassphrase: "123",
	});
	s.writeTarget("get", "/");
	const date = s.writeDateHeader();
	s.sign(function (err, authz) {
		t.error(err);
		const req = http.request(httpOptions, function (res) {
			t.end();
		});
		req.setHeader("date", date);
		req.setHeader("authorization", authz);
		req.end();
	});
});

test("createSigner with HMAC key", function (t) {
	const s = httpSignature.createSigner({
		keyId: "foo",
		key: hmacKey,
		algorithm: "hmac-sha256",
	});
	const date = s.writeDateHeader();
	s.writeTarget("get", "/");
	s.writeHeader("x-some-header", "bar");
	s.sign(function (err, authz) {
		t.error(err);
		const req = http.request(httpOptions, function (res) {
			t.end();
		});
		req.setHeader("date", date);
		req.setHeader("authorization", authz);
		req.setHeader("x-some-header", "bar");
		req.end();
	});
});

test("createSigner with sign function", function (t) {
	let date;
	const s = httpSignature.createSigner({
		sign: function (data, cb) {
			t.ok(typeof data === "string");
			const m = data.match(/^date: (.+)$/);
			t.ok(m);
			t.equal(m[1], date);
			cb(null, {
				keyId: "foo",
				algorithm: "hmac-sha256",
				signature: "fakesig",
			});
		},
	});
	date = s.writeDateHeader();
	s.sign(function (err, authz) {
		t.error(err);
		t.ok(authz.match(/fakesig/));
		const req = http.request(httpOptions, function (res) {
			t.end();
		});
		req.setHeader("date", date);
		req.setHeader("authorization", authz);
		req.end();
	});
});

test("ed25519", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: ed25519Private,
		algorithm: "ed25519-sha512",
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("tear down", function (t) {
	server.on("close", function () {
		t.end();
	});
	server.close();
});
