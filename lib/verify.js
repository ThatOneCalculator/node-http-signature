// Copyright 2015 Joyent, Inc.

const assert = require("assert-plus");
const crypto = require("crypto");
const sshpk = require("sshpk");
const utils = require("./utils");

const HASH_ALGOS = utils.HASH_ALGOS;
const PK_ALGOS = utils.PK_ALGOS;
const InvalidAlgorithmError = utils.InvalidAlgorithmError;
const HttpSignatureError = utils.HttpSignatureError;
const validateAlgorithm = utils.validateAlgorithm;

///--- Exported API

module.exports = {
	/**
	 * Verify RSA/DSA signature against public key.  You are expected to pass in
	 * an object that was returned from `parse()`.
	 *
	 * @param {Object} parsedSignature the object you got from `parse`.
	 * @param {String} pubkey RSA/DSA private key PEM.
	 * @return {Boolean} true if valid, false otherwise.
	 * @throws {TypeError} if you pass in bad arguments.
	 * @throws {InvalidAlgorithmError}
	 */
	verifySignature: function verifySignature(parsedSignature, pubkey) {
		assert.object(parsedSignature, "parsedSignature");
		if (typeof pubkey === "string" || Buffer.isBuffer(pubkey))
			pubkey = sshpk.parseKey(pubkey);
		assert.ok(sshpk.Key.isKey(pubkey, [1, 1]), "pubkey must be a sshpk.Key");

		const alg = validateAlgorithm(parsedSignature.algorithm, pubkey.type);
		if (alg[0] === "hmac" || alg[0] !== pubkey.type) return false;

		const v = pubkey.createVerify(alg[1]);
		v.update(parsedSignature.signingString);
		return v.verify(parsedSignature.params.signature, "base64");
	},

	/**
	 * Verify HMAC against shared secret.  You are expected to pass in an object
	 * that was returned from `parse()`.
	 *
	 * @param {Object} parsedSignature the object you got from `parse`.
	 * @param {String} or {Buffer} secret HMAC shared secret.
	 * @return {Boolean} true if valid, false otherwise.
	 * @throws {TypeError} if you pass in bad arguments.
	 * @throws {InvalidAlgorithmError}
	 */
	verifyHMAC: function verifyHMAC(parsedSignature, secret) {
		assert.object(parsedSignature, "parsedHMAC");
		assert(typeof secret === "string" || Buffer.isBuffer(secret));

		const alg = validateAlgorithm(parsedSignature.algorithm);
		if (alg[0] !== "hmac") return false;

		const hashAlg = alg[1].toUpperCase();

		const hmac = crypto.createHmac(hashAlg, secret);
		hmac.update(parsedSignature.signingString);

		/*
		 * Now double-hash to avoid leaking timing information - there's
		 * no easy constant-time compare in JS, so we use this approach
		 * instead. See for more info:
		 * https://www.isecpartners.com/blog/2011/february/double-hmac-
		 * verification.aspx
		 */
		let h1 = crypto.createHmac(hashAlg, secret);
		h1.update(hmac.digest());
		h1 = h1.digest();
		let h2 = crypto.createHmac(hashAlg, secret);
		h2.update(Buffer.from(parsedSignature.params.signature, "base64"));
		h2 = h2.digest();

		/* Node 0.8 returns strings from .digest(). */
		if (typeof h1 === "string") return h1 === h2;
		/* And node 0.10 lacks the .equals() method on Buffers. */
		if (Buffer.isBuffer(h1) && !h1.equals)
			return h1.toString("binary") === h2.toString("binary");

		return h1.equals(h2);
	},
};
