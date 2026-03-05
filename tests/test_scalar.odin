package secp256k1_tests

import "core:math/big"
import "core:testing"
import secp "../secp256k1"

@(test)
test_scalar_mul_1g :: proc(t: ^testing.T) {
	// 1 * G = G
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	k := make_int(1)
	defer big.destroy(&k)

	result: secp.Point
	defer secp.point_destroy(&result)

	err := secp.scalar_mul_point(&result, &k, &g, &params)
	testing.expect(t, err == .None, "scalar_mul_point should succeed")
	expect_point_eq(t, &result, &g, "1*G should equal G")
}

@(test)
test_scalar_mul_2g :: proc(t: ^testing.T) {
	// 2 * G = known 2G
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	k := make_int(2)
	defer big.destroy(&k)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.scalar_mul_point(&result, &k, &g, &params)

	expected := make_point(
		"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	)
	defer secp.point_destroy(&expected)

	expect_point_eq(t, &result, &expected, "2*G should match known coordinates")
}

@(test)
test_scalar_mul_3g :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	k := make_int(3)
	defer big.destroy(&k)

	result: secp.Point
	defer secp.point_destroy(&result)
	secp.scalar_mul_point(&result, &k, &g, &params)

	expected := make_point(
		"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	)
	defer secp.point_destroy(&expected)

	expect_point_eq(t, &result, &expected, "3*G should match known coordinates")
}

@(test)
test_scalar_mul_7g :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	k := make_int(7)
	defer big.destroy(&k)

	result: secp.Point
	defer secp.point_destroy(&result)
	secp.scalar_mul_point(&result, &k, &g, &params)

	expected := make_point(
		"5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
		"6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA",
	)
	defer secp.point_destroy(&expected)

	expect_point_eq(t, &result, &expected, "7*G should match known coordinates")
}

@(test)
test_scalar_mul_0 :: proc(t: ^testing.T) {
	// 0 * G = infinity
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	k := make_int(0)
	defer big.destroy(&k)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.scalar_mul_point(&result, &k, &g, &params)
	testing.expect(t, secp.point_is_infinity(&result), "0*G should be infinity")
}

@(test)
test_scalar_mul_n :: proc(t: ^testing.T) {
	// n * G = infinity (group order)
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.scalar_mul_point(&result, &params.n, &g, &params)
	testing.expect(t, secp.point_is_infinity(&result), "n*G should be infinity")
}

@(test)
test_privkey_to_pubkey :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	privkey := make_hex("EBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F")
	defer big.destroy(&privkey)

	pubkey: secp.Point
	defer secp.point_destroy(&pubkey)

	err := secp.privkey_to_pubkey(&pubkey, &privkey, &params)
	testing.expect(t, err == .None, "privkey_to_pubkey should succeed")

	expected := make_point(
		"779DD197A5DF977ED2CF6CB31D82D43328B790DC6B3B7D4437A427BD5847DFCD",
		"E94B724A555B6D017BB7607C3E3281DAF5B1699D6EF4124975C9237B917D426F",
	)
	defer secp.point_destroy(&expected)

	expect_point_eq(t, &pubkey, &expected, "pubkey should match known coordinates")
	expect_on_curve(t, &pubkey, &params, "pubkey should be on curve")
}

@(test)
test_scalar_mul_on_curve :: proc(t: ^testing.T) {
	// k*G should always be on the curve for various k values
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	for val in ([?]int{4, 5, 8, 100, 999}) {
		k := make_int(val)
		result: secp.Point

		secp.scalar_mul_point(&result, &k, &g, &params)
		expect_on_curve(t, &result, &params, "k*G should be on the curve")

		big.destroy(&k)
		secp.point_destroy(&result)
	}
}
