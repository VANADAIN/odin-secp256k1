package secp256k1_tests

import "core:math/big"
import "core:testing"
import secp "../secp256k1"

@(test)
test_curve_params_init :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	err := secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	testing.expect(t, err == .None, "init_curve_params should succeed")
}

@(test)
test_p_is_correct :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	p_str, _ := big.int_to_string(&params.p, 16)
	defer delete(p_str)
	testing.expect_value(t, p_str, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
}

@(test)
test_n_is_correct :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	n_str, _ := big.int_to_string(&params.n, 16)
	defer delete(n_str)
	testing.expect_value(t, n_str, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
}

@(test)
test_generator_on_curve :: proc(t: ^testing.T) {
	// Verify G satisfies y² = x³ + 7 (mod p)
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	lhs, rhs, x3: big.Int
	defer big.destroy(&lhs, &rhs, &x3)

	// lhs = gy² mod p
	big.sqrmod(&lhs, &params.gy, &params.p)

	// rhs = gx³ + 7 mod p
	big.sqrmod(&x3, &params.gx, &params.p)
	big.mulmod(&x3, &x3, &params.gx, &params.p)
	big.addmod(&rhs, &x3, &params.b, &params.p)

	eq, _ := big.equals(&lhs, &rhs)
	testing.expect(t, eq, "Generator point G must be on the curve")
}

@(test)
test_a_is_zero :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	is_z, _ := big.is_zero(&params.a)
	testing.expect(t, is_z, "a should be 0")
}

@(test)
test_b_is_seven :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	seven: big.Int
	defer big.destroy(&seven)
	big.set(&seven, 7)

	eq, _ := big.equals(&params.b, &seven)
	testing.expect(t, eq, "b should be 7")
}

@(test)
test_cofactor_is_one :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	one: big.Int
	defer big.destroy(&one)
	big.set(&one, 1)

	eq, _ := big.equals(&params.h, &one)
	testing.expect(t, eq, "cofactor h should be 1")
}
