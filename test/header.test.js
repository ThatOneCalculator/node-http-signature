// Copyright 2015 Joyent, Inc.  All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");

const test = require("tap").test;
const uuid = require("uuid").v4;

const httpSignature = require("../lib/index");

///--- Globals

let hmacKey = null;
let httpOptions = null;
let rsaPrivate = null;
let signOptions = null;
let server = null;
let socket = null;

///--- Tests

test("setup", function (t) {
	rsaPrivate = fs.readFileSync(`${__dirname}/rsa_private.pem`, "ascii");
	t.ok(rsaPrivate);

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
			method: "HEAD",
			headers: {
				"content-length": "0",
				"x-foo": "false",
			},
		};

		signOptions = {
			key: rsaPrivate,
			keyId: "unitTest",
		};

		t.end();
	});
});

test("header with 0 value", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "request-line", "content-length"],
	};

	t.ok(httpSignature.sign(req, opts));
	t.ok(req.getHeader("Authorization"));
	console.log(`> ${req.getHeader("Authorization")}`);
	req.end();
});

test("header with boolean-mungable value", function (t) {
	const req = http.request(httpOptions, function (res) {
		t.end();
	});
	const opts = {
		keyId: "unit",
		key: rsaPrivate,
		headers: ["date", "x-foo"],
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
