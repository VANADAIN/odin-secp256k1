package secp256k1_tests

import "core:crypto/hash"
import "core:math/big"
import "core:testing"
import secp "../secp256k1"

// Known-answer test vectors from bitcoin-core/secp256k1 and Ethereum.

// Scalar multiplication vectors: k * G = expected point
Scalar_Vector :: struct {
	k_hex:  string,
	x_hex:  string,
	y_hex:  string,
}

SCALAR_VECTORS :: [?]Scalar_Vector{
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000002",
		"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000003",
		"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000004",
		"E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
		"51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000005",
		"2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
		"D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000007",
		"5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
		"6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000008",
		"2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01",
		"5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904",
	},
	// Larger scalar
	{
		"EBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F",
		"779DD197A5DF977ED2CF6CB31D82D43328B790DC6B3B7D4437A427BD5847DFCD",
		"E94B724A555B6D017BB7607C3E3281DAF5B1699D6EF4124975C9237B917D426F",
	},
}

@(test)
test_scalar_mul_vectors :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	for vec in SCALAR_VECTORS {
		k := make_hex(vec.k_hex)
		result: secp.Point

		err := secp.scalar_mul_point(&result, &k, &g, &params)
		testing.expect(t, err == .None, "scalar_mul_point should succeed")

		expected := make_point(vec.x_hex, vec.y_hex)
		expect_point_eq(t, &result, &expected, "k*G should match known vector")

		big.destroy(&k)
		secp.point_destroy(&result)
		secp.point_destroy(&expected)
	}
}

// ECDSA sign + verify + recover roundtrip for multiple keys/messages
ECDSA_Vector :: struct {
	privkey_hex:  string,
	message:      string,
	expected_r:   string,
	expected_s:   string,
	expected_v:   u8,
}

ECDSA_VECTORS :: [?]ECDSA_Vector{
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"hello",
		"0F2FFF8620D8FFE97040F8CF72AE476EF8FF4412373929C0324CE8428D3352E7",
		"1845AE4903027667005846F8F0BE3E5ED2DB5C3826BA83A6E542E080792F9A9D",
		0,
	},
	{
		"EBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F",
		"test message",
		"A21C0F2336D29C3C2452BDB8114E460C2609F2BC42BCFCBDEBF4840EA4AF661B",
		"0A327C5458F43E3A309C8AAB9FCF0304372CAFA127997267298009E90AAADEA8",
		1,
	},
}

@(test)
test_ecdsa_known_vectors :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	for vec in ECDSA_VECTORS {
		privkey := make_hex(vec.privkey_hex)
		msg_hash := sha256_hash(transmute([]u8)vec.message)

		sig: secp.Signature
		sign_err := secp.sign(&sig, &privkey, msg_hash, &params)
		testing.expect(t, sign_err == .None, "sign should succeed")

		// Check r, s, v
		exp_r := make_hex(vec.expected_r)
		exp_s := make_hex(vec.expected_s)
		eq_r, _ := big.equals(&sig.r, &exp_r)
		eq_s, _ := big.equals(&sig.s, &exp_s)
		testing.expect(t, eq_r, "r should match known vector")
		testing.expect(t, eq_s, "s should match known vector")
		testing.expect(t, sig.v == vec.expected_v, "v should match known vector")

		// Verify signature
		pubkey: secp.Point
		secp.privkey_to_pubkey(&pubkey, &privkey, &params)
		verify_err := secp.verify(&pubkey, msg_hash, &sig, &params)
		testing.expect(t, verify_err == .None, "verify should succeed")

		// Recover pubkey
		recovered: secp.Point
		recover_err := secp.recover_pubkey(&recovered, msg_hash, &sig, sig.v, &params)
		testing.expect(t, recover_err == .None, "recover should succeed")
		expect_point_eq(t, &recovered, &pubkey, "recovered pubkey should match")

		big.destroy(&privkey, &exp_r, &exp_s)
		secp.signature_destroy(&sig)
		secp.point_destroy(&pubkey, &recovered)
	}
}

// Test serialization roundtrip with known vectors
@(test)
test_serialize_roundtrip_vectors :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	for vec in SCALAR_VECTORS {
		k := make_hex(vec.k_hex)
		pt: secp.Point
		secp.scalar_mul_point(&pt, &k, &g, &params)

		// Uncompressed roundtrip
		buf_u: [65]u8
		secp.serialize_point_uncompressed(&buf_u, &pt, &params)
		result_u: secp.Point
		err_u := secp.deserialize_point(&result_u, buf_u[:], &params)
		testing.expect(t, err_u == .None, "uncompressed deserialize should succeed")
		expect_point_eq(t, &result_u, &pt, "uncompressed roundtrip should match")

		// Compressed roundtrip
		buf_c: [33]u8
		secp.serialize_point_compressed(&buf_c, &pt, &params)
		result_c: secp.Point
		err_c := secp.deserialize_point(&result_c, buf_c[:], &params)
		testing.expect(t, err_c == .None, "compressed deserialize should succeed")
		expect_point_eq(t, &result_c, &pt, "compressed roundtrip should match")

		big.destroy(&k)
		secp.point_destroy(&pt, &result_u, &result_c)
	}
}
