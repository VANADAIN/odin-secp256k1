package secp256k1_tests

import "core:math/big"
import "core:testing"
import secp "../secp256k1"

// Helper: create a point from hex strings
make_point :: proc(x_hex, y_hex: string) -> secp.Point {
	pt: secp.Point
	big.atoi(&pt.x, x_hex, 16)
	big.atoi(&pt.y, y_hex, 16)
	return pt
}

// Helper: check two points are equal
expect_point_eq :: proc(t: ^testing.T, a, b: ^secp.Point, msg: string) {
	if secp.point_is_infinity(a) && secp.point_is_infinity(b) {
		return
	}
	if secp.point_is_infinity(a) || secp.point_is_infinity(b) {
		testing.expect(t, false, msg)
		return
	}
	eq_x, _ := big.equals(&a.x, &b.x)
	eq_y, _ := big.equals(&a.y, &b.y)
	testing.expect(t, eq_x && eq_y, msg)
}

// Helper: check point is on curve (y² = x³ + 7 mod p)
expect_on_curve :: proc(t: ^testing.T, pt: ^secp.Point, params: ^secp.Curve_Params, msg: string) {
	if secp.point_is_infinity(pt) do return

	lhs, rhs, x3: big.Int
	defer big.destroy(&lhs, &rhs, &x3)

	big.sqrmod(&lhs, &pt.y, &params.p)
	big.sqrmod(&x3, &pt.x, &params.p)
	big.mulmod(&x3, &x3, &pt.x, &params.p)
	big.addmod(&rhs, &x3, &params.b, &params.p)

	eq, _ := big.equals(&lhs, &rhs)
	testing.expect(t, eq, msg)
}

@(test)
test_point_infinity :: proc(t: ^testing.T) {
	inf := secp.point_infinity()
	defer secp.point_destroy(&inf)
	testing.expect(t, secp.point_is_infinity(&inf), "point_infinity should be infinity")
}

@(test)
test_point_not_infinity :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)
	testing.expect(t, !secp.point_is_infinity(&g), "G should not be infinity")
}

@(test)
test_point_double_g :: proc(t: ^testing.T) {
	// 2G should be on the curve and not infinity
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	result: secp.Point
	defer secp.point_destroy(&result)

	err := secp.point_double(&result, &g, &params)
	testing.expect(t, err == .None, "point_double should succeed")
	testing.expect(t, !secp.point_is_infinity(&result), "2G should not be infinity")
	expect_on_curve(t, &result, &params, "2G should be on the curve")
}

@(test)
test_point_double_g_known_value :: proc(t: ^testing.T) {
	// 2G has known coordinates
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	result: secp.Point
	defer secp.point_destroy(&result)
	secp.point_double(&result, &g, &params)

	// Known 2G coordinates
	expected := make_point(
		"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	)
	defer secp.point_destroy(&expected)

	expect_point_eq(t, &result, &expected, "2G should match known coordinates")
}

@(test)
test_point_add_g_plus_g :: proc(t: ^testing.T) {
	// G + G should equal 2G (from point_double)
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	doubled, added: secp.Point
	defer secp.point_destroy(&doubled, &added)

	secp.point_double(&doubled, &g, &params)
	err := secp.point_add(&added, &g, &g, &params)
	testing.expect(t, err == .None, "point_add should succeed")
	expect_point_eq(t, &added, &doubled, "G + G should equal 2G")
}

@(test)
test_point_add_g_plus_2g :: proc(t: ^testing.T) {
	// G + 2G = 3G, should be on curve
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	two_g, three_g: secp.Point
	defer secp.point_destroy(&two_g, &three_g)

	secp.point_double(&two_g, &g, &params)
	secp.point_add(&three_g, &g, &two_g, &params)

	expect_on_curve(t, &three_g, &params, "3G should be on the curve")

	// Known 3G coordinates
	expected := make_point(
		"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	)
	defer secp.point_destroy(&expected)
	expect_point_eq(t, &three_g, &expected, "3G should match known coordinates")
}

@(test)
test_point_add_infinity_left :: proc(t: ^testing.T) {
	// O + G = G
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	inf := secp.point_infinity()
	defer secp.point_destroy(&g, &inf)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.point_add(&result, &inf, &g, &params)
	expect_point_eq(t, &result, &g, "O + G should equal G")
}

@(test)
test_point_add_infinity_right :: proc(t: ^testing.T) {
	// G + O = G
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	inf := secp.point_infinity()
	defer secp.point_destroy(&g, &inf)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.point_add(&result, &g, &inf, &params)
	expect_point_eq(t, &result, &g, "G + O should equal G")
}

@(test)
test_point_add_inverse :: proc(t: ^testing.T) {
	// G + (-G) = O
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	neg_g: secp.Point
	defer secp.point_destroy(&g, &neg_g)

	// -G has same x, negated y
	big.set(&neg_g.x, &g.x)
	big.sub(&neg_g.y, &params.p, &g.y)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.point_add(&result, &g, &neg_g, &params)
	testing.expect(t, secp.point_is_infinity(&result), "G + (-G) should be infinity")
}

@(test)
test_point_double_infinity :: proc(t: ^testing.T) {
	// 2 * O = O
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	inf := secp.point_infinity()
	defer secp.point_destroy(&inf)

	result: secp.Point
	defer secp.point_destroy(&result)

	secp.point_double(&result, &inf, &params)
	testing.expect(t, secp.point_is_infinity(&result), "2 * O should be infinity")
}

@(test)
test_point_add_commutativity :: proc(t: ^testing.T) {
	// G + 2G == 2G + G
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	two_g, r1, r2: secp.Point
	defer secp.point_destroy(&g, &two_g, &r1, &r2)

	secp.point_double(&two_g, &g, &params)
	secp.point_add(&r1, &g, &two_g, &params)
	secp.point_add(&r2, &two_g, &g, &params)

	expect_point_eq(t, &r1, &r2, "G + 2G should equal 2G + G")
}
