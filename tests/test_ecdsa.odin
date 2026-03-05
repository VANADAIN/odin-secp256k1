package secp256k1_tests

import "core:crypto/hash"
import "core:math/big"
import "core:testing"
import secp "../secp256k1"

// Helper: SHA-256 hash of a byte string
sha256_hash :: proc(data: []u8) -> [32]u8 {
	result: [32]u8
	hash.hash_bytes_to_buffer(hash.Algorithm.SHA256, data, result[:])
	return result
}

@(test)
test_ecdsa_sign_verify :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	// privkey = 1
	privkey := make_int(1)
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("hello"))

	// Sign
	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	sign_err := secp.sign(&sig, &privkey, msg_hash, &params)
	testing.expect(t, sign_err == .None, "sign should succeed")

	// Verify
	pubkey: secp.Point
	defer secp.point_destroy(&pubkey)
	secp.privkey_to_pubkey(&pubkey, &privkey, &params)

	verify_err := secp.verify(&pubkey, msg_hash, &sig, &params)
	testing.expect(t, verify_err == .None, "verify should succeed")
}

@(test)
test_ecdsa_sign_known_vector_1 :: proc(t: ^testing.T) {
	// privkey=1, msg="hello"
	// Expected from RFC 6979 reference implementation
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_int(1)
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("hello"))

	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	expected_r := make_hex("0F2FFF8620D8FFE97040F8CF72AE476EF8FF4412373929C0324CE8428D3352E7")
	expected_s := make_hex("1845AE4903027667005846F8F0BE3E5ED2DB5C3826BA83A6E542E080792F9A9D")
	defer big.destroy(&expected_r, &expected_s)

	eq_r, _ := big.equals(&sig.r, &expected_r)
	eq_s, _ := big.equals(&sig.s, &expected_s)
	testing.expect(t, eq_r, "r should match known vector")
	testing.expect(t, eq_s, "s should match known vector")
	testing.expect(t, sig.v == 0, "v should be 0")
}

@(test)
test_ecdsa_sign_known_vector_2 :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_hex("EBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F")
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("test message"))

	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	expected_r := make_hex("A21C0F2336D29C3C2452BDB8114E460C2609F2BC42BCFCBDEBF4840EA4AF661B")
	expected_s := make_hex("0A327C5458F43E3A309C8AAB9FCF0304372CAFA127997267298009E90AAADEA8")
	defer big.destroy(&expected_r, &expected_s)

	eq_r, _ := big.equals(&sig.r, &expected_r)
	eq_s, _ := big.equals(&sig.s, &expected_s)
	testing.expect(t, eq_r, "r should match known vector 2")
	testing.expect(t, eq_s, "s should match known vector 2")
	testing.expect(t, sig.v == 1, "v should be 1")
}

@(test)
test_ecdsa_verify_rejects_wrong_message :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_int(1)
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("hello"))
	wrong_hash := sha256_hash(transmute([]u8)string("wrong"))

	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	pubkey: secp.Point
	defer secp.point_destroy(&pubkey)
	secp.privkey_to_pubkey(&pubkey, &privkey, &params)

	verify_err := secp.verify(&pubkey, wrong_hash, &sig, &params)
	testing.expect(t, verify_err != .None, "verify should fail with wrong message")
}

@(test)
test_ecdsa_verify_rejects_wrong_key :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_int(1)
	wrong_privkey := make_int(2)
	defer big.destroy(&privkey, &wrong_privkey)

	msg_hash := sha256_hash(transmute([]u8)string("hello"))

	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	wrong_pubkey: secp.Point
	defer secp.point_destroy(&wrong_pubkey)
	secp.privkey_to_pubkey(&wrong_pubkey, &wrong_privkey, &params)

	verify_err := secp.verify(&wrong_pubkey, msg_hash, &sig, &params)
	testing.expect(t, verify_err != .None, "verify should fail with wrong pubkey")
}

@(test)
test_ecdsa_recover :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_int(1)
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("hello"))

	// Sign
	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	// Get expected pubkey
	expected_pubkey: secp.Point
	defer secp.point_destroy(&expected_pubkey)
	secp.privkey_to_pubkey(&expected_pubkey, &privkey, &params)

	// Recover
	recovered: secp.Point
	defer secp.point_destroy(&recovered)
	recover_err := secp.recover_pubkey(&recovered, msg_hash, &sig, sig.v, &params)
	testing.expect(t, recover_err == .None, "recover_pubkey should succeed")

	expect_point_eq(t, &recovered, &expected_pubkey, "recovered pubkey should match original")
}

@(test)
test_ecdsa_recover_vector_2 :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_hex("EBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F")
	defer big.destroy(&privkey)

	msg_hash := sha256_hash(transmute([]u8)string("test message"))

	sig: secp.Signature
	defer secp.signature_destroy(&sig)
	secp.sign(&sig, &privkey, msg_hash, &params)

	expected_pubkey: secp.Point
	defer secp.point_destroy(&expected_pubkey)
	secp.privkey_to_pubkey(&expected_pubkey, &privkey, &params)

	recovered: secp.Point
	defer secp.point_destroy(&recovered)
	recover_err := secp.recover_pubkey(&recovered, msg_hash, &sig, sig.v, &params)
	testing.expect(t, recover_err == .None, "recover_pubkey should succeed")
	expect_point_eq(t, &recovered, &expected_pubkey, "recovered pubkey should match")
}

@(test)
test_ecdsa_invalid_privkey_zero :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_int(0)
	defer big.destroy(&privkey)

	msg_hash: [32]u8
	sig: secp.Signature
	defer secp.signature_destroy(&sig)

	err := secp.sign(&sig, &privkey, msg_hash, &params)
	testing.expect(t, err == .Invalid_Private_Key, "signing with zero key should fail")
}

@(test)
test_ecdsa_invalid_recovery_id :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	msg_hash: [32]u8
	sig: secp.Signature
	big.set(&sig.r, 1)
	big.set(&sig.s, 1)
	defer secp.signature_destroy(&sig)

	recovered: secp.Point
	defer secp.point_destroy(&recovered)

	err := secp.recover_pubkey(&recovered, msg_hash, &sig, 5, &params)
	testing.expect(t, err == .Invalid_Recovery_Id, "recovery_id > 1 should fail")
}
