// Copyright 2012 Joyent, Inc.  All rights reserved.

const assert = require("assert-plus");
const crypto = require("crypto");
const util = require("util");
const sshpk = require("sshpk");
const jsprim = require("jsprim");
const utils = require("./utils");

const sprintf = require("util").format;

const HASH_ALGOS = utils.HASH_ALGOS;
const PK_ALGOS = utils.PK_ALGOS;
const InvalidAlgorithmError = utils.InvalidAlgorithmError;
const HttpSignatureError = utils.HttpSignatureError;
const validateAlgorithm = utils.validateAlgorithm;

///--- Globals

const AUTHZ_PARAMS = [
	"keyId",
	"algorithm",
	"created",
	"expires",
	"opaque",
	"headers",
	"signature",
];

///--- Specific Errors

function MissingHeaderError(message) {
	HttpSignatureError.call(this, message, MissingHeaderError);
}
util.inherits(MissingHeaderError, HttpSignatureError);

function StrictParsingError(message) {
	HttpSignatureError.call(this, message, StrictParsingError);
}
util.inherits(StrictParsingError, HttpSignatureError);

function FormatAuthz(prefix, params) {
	assert.string(prefix, "prefix");
	assert.object(params, "params");

	let authz = "";
	for (let i = 0; i < AUTHZ_PARAMS.length; i++) {
		const param = AUTHZ_PARAMS[i];
		const value = params[param];
		if (value === undefined) continue;
		if (typeof value === "number") {
			authz += prefix + sprintf("%s=%d", param, value);
		} else {
			assert.string(value, `params.${param}`);

			authz += prefix + sprintf('%s="%s"', param, value);
		}
		prefix = ",";
	}

	return authz;
}

/* See createSigner() */
function RequestSigner(options) {
	assert.object(options, "options");

	let alg = [];
	if (options.algorithm !== undefined) {
		assert.string(options.algorithm, "options.algorithm");
		alg = validateAlgorithm(options.algorithm);
	}
	this.rs_alg = alg;

	/*
	 * RequestSigners come in two varieties: ones with an rs_signFunc, and ones
	 * with an rs_signer.
	 *
	 * rs_signFunc-based RequestSigners have to build up their entire signing
	 * string within the rs_lines array and give it to rs_signFunc as a single
	 * concat'd blob. rs_signer-based RequestSigners can add a line at a time to
	 * their signing state by using rs_signer.update(), thus only needing to
	 * buffer the hash function state and one line at a time.
	 */
	if (options.sign !== undefined) {
		assert.func(options.sign, "options.sign");
		this.rs_signFunc = options.sign;
	} else if (alg[0] === "hmac" && options.key !== undefined) {
		assert.string(options.keyId, "options.keyId");
		this.rs_keyId = options.keyId;

		if (typeof options.key !== "string" && !Buffer.isBuffer(options.key))
			throw new TypeError("options.key for HMAC must be a string or Buffer");

		/*
		 * Make an rs_signer for HMACs, not a rs_signFunc -- HMACs digest their
		 * data in chunks rather than requiring it all to be given in one go
		 * at the end, so they are more similar to signers than signFuncs.
		 */
		this.rs_signer = crypto.createHmac(alg[1].toUpperCase(), options.key);
		this.rs_signer.sign = function () {
			const digest = this.digest("base64");
			return {
				hashAlgorithm: alg[1],
				toString: function () {
					return digest;
				},
			};
		};
	} else if (options.key !== undefined) {
		let key = options.key;
		if (typeof key === "string" || Buffer.isBuffer(key))
			assert.optionalString(options.keyPassphrase, "options.keyPassphrase");
		key = sshpk.parsePrivateKey(key, "auto", {
			passphrase: options.keyPassphrase,
		});

		assert.ok(
			sshpk.PrivateKey.isPrivateKey(key, [1, 2]),
			"options.key must be a sshpk.PrivateKey",
		);
		this.rs_key = key;

		assert.string(options.keyId, "options.keyId");
		this.rs_keyId = options.keyId;

		if (!PK_ALGOS[key.type]) {
			throw new InvalidAlgorithmError(
				`${key.type.toUpperCase()} type keys are not supported`,
			);
		}

		if (alg[0] !== undefined && key.type !== alg[0]) {
			throw new InvalidAlgorithmError(
				`options.key must be a ${alg[0].toUpperCase()} key, was given a ${key.type.toUpperCase()} key instead`,
			);
		}

		this.rs_signer = key.createSign(alg[1]);
	} else {
		throw new TypeError("options.sign (func) or options.key is required");
	}

	this.rs_headers = [];
	this.rs_lines = [];
}

/**
 * Adds a header to be signed, with its value, into this signer.
 *
 * @param {String} header
 * @param {String} value
 * @return {String} value written
 */
RequestSigner.prototype.writeHeader = function (header, value) {
	assert.string(header, "header");
	header = header.toLowerCase();
	assert.string(value, "value");

	this.rs_headers.push(header);

	if (this.rs_signFunc) {
		this.rs_lines.push(`${header}: ${value}`);
	} else {
		const line =
			this.rs_headers.length > 1
				? `\n${header}: ${value}`
				: `${header}: ${value}`;
		this.rs_signer.update(line);
	}

	return value;
};

/**
 * Adds a default Date header, returning its value.
 *
 * @return {String}
 */
RequestSigner.prototype.writeDateHeader = function () {
	return this.writeHeader("date", jsprim.rfc1123(new Date()));
};

/**
 * Adds the request target line to be signed.
 *
 * @param {String} method, HTTP method (e.g. 'get', 'post', 'put')
 * @param {String} path
 */
RequestSigner.prototype.writeTarget = function (method, path) {
	assert.string(method, "method");
	assert.string(path, "path");
	method = method.toLowerCase();
	this.writeHeader("(request-target)", `${method} ${path}`);
};

/**
 * Calculate the value for the Authorization header on this request
 * asynchronously.
 *
 * @param {Func} callback (err, authz)
 */
RequestSigner.prototype.sign = function (cb) {
	assert.func(cb, "callback");

	if (this.rs_headers.length < 1)
		throw new Error("At least one header must be signed");

	let alg;
	let authz;
	if (this.rs_signFunc) {
		const data = this.rs_lines.join("\n");
		const self = this;
		this.rs_signFunc(data, function (err, sig) {
			if (err) {
				cb(err);
				return;
			}
			try {
				assert.object(sig, "signature");
				assert.string(sig.keyId, "signature.keyId");
				assert.string(sig.algorithm, "signature.algorithm");
				assert.string(sig.signature, "signature.signature");
				alg = validateAlgorithm(sig.algorithm);

				authz = FormatAuthz("Signature ", {
					keyId: sig.keyId,
					algorithm: sig.algorithm,
					headers: self.rs_headers.join(" "),
					signature: sig.signature,
				});
			} catch (e) {
				cb(e);
				return;
			}
			cb(null, authz);
		});
	} else {
		try {
			const sigObj = this.rs_signer.sign();
		} catch (e) {
			cb(e);
			return;
		}
		alg = sigObj.hideAlgorithm
			? "hs2019"
			: `${this.rs_alg[0] || this.rs_key.type}-${sigObj.hashAlgorithm}`;
		const signature = sigObj.toString();
		authz = FormatAuthz("Signature ", {
			keyId: this.rs_keyId,
			algorithm: alg,
			headers: this.rs_headers.join(" "),
			signature: signature,
		});
		cb(null, authz);
	}
};

///--- Exported API

module.exports = {
	/**
	 * Identifies whether a given object is a request signer or not.
	 *
	 * @param {Object} object, the object to identify
	 * @returns {Boolean}
	 */
	isSigner: function (obj) {
		if (typeof obj === "object" && obj instanceof RequestSigner) return true;
		return false;
	},

	/**
	 * Creates a request signer, used to asynchronously build a signature
	 * for a request (does not have to be an http.ClientRequest).
	 *
	 * @param {Object} options, either:
	 *                   - {String} keyId
	 *                   - {String|Buffer} key
	 *                   - {String} algorithm (optional, required for HMAC)
	 *                   - {String} keyPassphrase (optional, not for HMAC)
	 *                 or:
	 *                   - {Func} sign (data, cb)
	 * @return {RequestSigner}
	 */
	createSigner: function createSigner(options) {
		return new RequestSigner(options);
	},

	/**
	 * Adds an 'Authorization' header to an http.ClientRequest object.
	 *
	 * Note that this API will add a Date header if it's not already set. Any
	 * other headers in the options.headers array MUST be present, or this
	 * will throw.
	 *
	 * You shouldn't need to check the return type; it's just there if you want
	 * to be pedantic.
	 *
	 * The optional flag indicates whether parsing should use strict enforcement
	 * of the version draft-cavage-http-signatures-04 of the spec or beyond.
	 * The default is to be loose and support
	 * older versions for compatibility.
	 *
	 * @param {Object} request an instance of http.ClientRequest.
	 * @param {Object} options signing parameters object:
	 *                   - {String} keyId required.
	 *                   - {String} key required (either a PEM or HMAC key).
	 *                   - {Array} headers optional; defaults to ['date'].
	 *                   - {String} algorithm optional (unless key is HMAC);
	 *                              default is the same as the sshpk default
	 *                              signing algorithm for the type of key given
	 *                   - {String} httpVersion optional; defaults to '1.1'.
	 *                   - {Boolean} strict optional; defaults to 'false'.
	 *                   - {int}    expiresIn optional; defaults to 60. The
	 *                              seconds after which the signature should
	 *                              expire;
	 *                   - {String} keyPassphrase optional; The passphrase to
	 *                              pass to sshpk to parse the privateKey.
	 *                              This doesn't do anything if algorithm is
	 *                              HMAC.
	 *                   - {Boolean} hideAlgorithm optional; defaults to 'false'.
	 *                               if true, hides algorithm by writing "hs2019"
	 *                               to signature.
	 * @return {Boolean} true if Authorization (and optionally Date) were added.
	 * @throws {TypeError} on bad parameter types (input).
	 * @throws {InvalidAlgorithmError} if algorithm was bad or incompatible with
	 *                                 the given key.
	 * @throws {sshpk.KeyParseError} if key was bad.
	 * @throws {MissingHeaderError} if a header to be signed was specified but
	 *                              was not present.
	 */
	signRequest: function signRequest(request, options) {
		assert.object(request, "request");
		assert.object(options, "options");
		assert.optionalString(options.algorithm, "options.algorithm");
		assert.string(options.keyId, "options.keyId");
		assert.optionalString(options.opaque, "options.opaque");
		assert.optionalArrayOfString(options.headers, "options.headers");
		assert.optionalString(options.httpVersion, "options.httpVersion");
		assert.optionalNumber(options.expiresIn, "options.expiresIn");
		assert.optionalString(options.keyPassphrase, "options.keyPassphrase");
		assert.optionalBool(options.hideAlgorithm, "options.hideAlgorithm");

		if (!request.getHeader("Date"))
			request.setHeader("Date", jsprim.rfc1123(new Date()));
		let headers = ["date"];
		if (options.headers) headers = options.headers;
		if (!options.httpVersion) options.httpVersion = "1.1";

		let alg = [];
		if (options.algorithm) {
			options.algorithm = options.algorithm.toLowerCase();
			alg = validateAlgorithm(options.algorithm);
		}

		let key = options.key;
		if (alg[0] === "hmac") {
			if (typeof key !== "string" && !Buffer.isBuffer(key))
				throw new TypeError("options.key must be a string or Buffer");
		} else {
			if (typeof key === "string" || Buffer.isBuffer(key))
				key = sshpk.parsePrivateKey(options.key, "auto", {
					passphrase: options.keyPassphrase,
				});

			assert.ok(
				sshpk.PrivateKey.isPrivateKey(key, [1, 2]),
				"options.key must be a sshpk.PrivateKey",
			);

			if (!PK_ALGOS[key.type]) {
				throw new InvalidAlgorithmError(
					`${key.type.toUpperCase()} type keys are not supported`,
				);
			}

			if (alg[0] === undefined) {
				alg[0] = key.type;
			} else if (key.type !== alg[0]) {
				throw new InvalidAlgorithmError(
					`options.key must be a ${alg[0].toUpperCase()} key, was given a ${key.type.toUpperCase()} key instead`,
				);
			}
			if (alg[1] === undefined) {
				alg[1] = key.defaultHashAlgorithm();
			}

			options.algorithm = options.hideAlgorithm
				? "hs2019"
				: `${alg[0]}-${alg[1]}`;
		}

		const params = {
			keyId: options.keyId,
			algorithm: options.algorithm,
		};

		let i;
		let stringToSign = "";
		for (i = 0; i < headers.length; i++) {
			if (typeof headers[i] !== "string")
				throw new TypeError("options.headers must be an array of Strings");

			const h = headers[i].toLowerCase();

			if (h === "request-line") {
				if (!options.strict) {
					/**
					 * We allow headers from the older spec drafts if strict parsing isn't
					 * specified in options.
					 */
					stringToSign += `${request.method} ${request.path} HTTP/${options.httpVersion}`;
				} else {
					/* Strict parsing doesn't allow older draft headers. */
					throw new StrictParsingError(
						"request-line is not a valid header " +
							"with strict parsing enabled.",
					);
				}
			} else if (h === "(request-target)") {
				stringToSign += `(request-target): ${request.method.toLowerCase()} ${
					request.path
				}`;
			} else if (h === "(keyid)") {
				stringToSign += `(keyid): ${options.keyId}`;
			} else if (h === "(algorithm)") {
				stringToSign += `(algorithm): ${options.algorithm}`;
			} else if (h === "(opaque)") {
				const opaque = options.opaque;
				if (opaque === undefined || opaque === "") {
					throw new MissingHeaderError("options.opaque was not in the request");
				}
				stringToSign += `(opaque): ${opaque}`;
			} else if (h === "(created)") {
				const created = Math.floor(Date.now() / 1000);
				params.created = created;
				stringToSign += `(created): ${created}`;
			} else if (h === "(expires)") {
				let expiresIn = options.expiresIn;
				if (expiresIn === undefined) {
					expiresIn = 60;
				}
				const expires = Math.floor(Date.now() / 1000) + expiresIn;
				params.expires = expires;
				stringToSign += `(expires): ${expires}`;
			} else {
				const value = request.getHeader(h);
				if (value === undefined || value === "") {
					throw new MissingHeaderError(`${h} was not in the request`);
				}
				stringToSign += `${h}: ${value}`;
			}

			if (i + 1 < headers.length) stringToSign += "\n";
		}

		/* This is just for unit tests. */
		if (Object.prototype.hasOwnProperty.call(request, "_stringToSign")) {
			request._stringToSign = stringToSign;
		}

		let signature;
		if (alg[0] === "hmac") {
			const hmac = crypto.createHmac(alg[1].toUpperCase(), key);
			hmac.update(stringToSign);
			signature = hmac.digest("base64");
		} else {
			const signer = key.createSign(alg[1]);
			signer.update(stringToSign);
			const sigObj = signer.sign();
			if (!HASH_ALGOS[sigObj.hashAlgorithm]) {
				throw new InvalidAlgorithmError(
					`${sigObj.hashAlgorithm.toUpperCase()} is not a supported hash algorithm`,
				);
			}
			assert.strictEqual(
				alg[1],
				sigObj.hashAlgorithm,
				"hash algorithm mismatch",
			);
			signature = sigObj.toString();
			assert.notStrictEqual(signature, "", "empty signature produced");
		}

		const authzHeaderName = options.authorizationHeaderName || "Authorization";
		const prefix =
			authzHeaderName.toLowerCase() === utils.HEADER.SIG ? "" : "Signature ";

		params.signature = signature;

		if (options.opaque) params.opaque = options.opaque;
		if (options.headers) params.headers = options.headers.join(" ");

		request.setHeader(authzHeaderName, FormatAuthz(prefix, params));

		return true;
	},
};
