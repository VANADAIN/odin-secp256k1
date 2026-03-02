package secp256k1_tests

import "core:math/big"
import "core:testing"
import secp "../secp256k1"

// Helper to create a big.Int from an integer
make_int :: proc(val: int) -> big.Int {
	result: big.Int
	big.set(&result, val)
	return result
}

// Helper to create a big.Int from a hex string
make_hex :: proc(hex: string) -> big.Int {
	result: big.Int
	big.atoi(&result, hex, 16)
	return result
}

expect_int_eq :: proc(t: ^testing.T, a: ^big.Int, expected: int, msg: string) {
	b := make_int(expected)
	defer big.destroy(&b)
	eq, _ := big.equals(a, &b)
	testing.expect(t, eq, msg)
}

@(test)
test_field_add_basic :: proc(t: ^testing.T) {
	// (3 + 5) mod 7 = 1
	p := make_int(7)
	a := make_int(3)
	b := make_int(5)
	result: big.Int
	defer big.destroy(&p, &a, &b, &result)

	err := secp.field_add(&result, &a, &b, &p)
	testing.expect(t, err == .None, "field_add should succeed")
	expect_int_eq(t, &result, 1, "(3+5) mod 7 should be 1")
}

@(test)
test_field_add_no_wrap :: proc(t: ^testing.T) {
	// (2 + 3) mod 7 = 5
	p := make_int(7)
	a := make_int(2)
	b := make_int(3)
	result: big.Int
	defer big.destroy(&p, &a, &b, &result)

	secp.field_add(&result, &a, &b, &p)
	expect_int_eq(t, &result, 5, "(2+3) mod 7 should be 5")
}

@(test)
test_field_sub_basic :: proc(t: ^testing.T) {
	// (3 - 5) mod 7 = 5 (wraps to positive)
	p := make_int(7)
	a := make_int(3)
	b := make_int(5)
	result: big.Int
	defer big.destroy(&p, &a, &b, &result)

	err := secp.field_sub(&result, &a, &b, &p)
	testing.expect(t, err == .None, "field_sub should succeed")
	expect_int_eq(t, &result, 5, "(3-5) mod 7 should be 5")
}

@(test)
test_field_mul_basic :: proc(t: ^testing.T) {
	// (3 * 5) mod 7 = 1
	p := make_int(7)
	a := make_int(3)
	b := make_int(5)
	result: big.Int
	defer big.destroy(&p, &a, &b, &result)

	err := secp.field_mul(&result, &a, &b, &p)
	testing.expect(t, err == .None, "field_mul should succeed")
	expect_int_eq(t, &result, 1, "(3*5) mod 7 should be 1")
}

@(test)
test_field_inv_basic :: proc(t: ^testing.T) {
	// 3^(-1) mod 7 = 5  (because 3*5 = 15 = 1 mod 7)
	p := make_int(7)
	a := make_int(3)
	result: big.Int
	defer big.destroy(&p, &a, &result)

	err := secp.field_inv(&result, &a, &p)
	testing.expect(t, err == .None, "field_inv should succeed")
	expect_int_eq(t, &result, 5, "3^(-1) mod 7 should be 5")
}

@(test)
test_field_inv_zero :: proc(t: ^testing.T) {
	p := make_int(7)
	a := make_int(0)
	result: big.Int
	defer big.destroy(&p, &a, &result)

	err := secp.field_inv(&result, &a, &p)
	testing.expect(t, err == .Zero_Inverse, "inverse of 0 should return Zero_Inverse")
}

@(test)
test_field_pow_basic :: proc(t: ^testing.T) {
	// 3^4 mod 7 = 81 mod 7 = 4
	p := make_int(7)
	a := make_int(3)
	exp := make_int(4)
	result: big.Int
	defer big.destroy(&p, &a, &exp, &result)

	err := secp.field_pow(&result, &a, &exp, &p)
	testing.expect(t, err == .None, "field_pow should succeed")
	expect_int_eq(t, &result, 4, "3^4 mod 7 should be 4")
}

@(test)
test_field_pow_zero_exp :: proc(t: ^testing.T) {
	// a^0 mod p = 1
	p := make_int(7)
	a := make_int(3)
	exp := make_int(0)
	result: big.Int
	defer big.destroy(&p, &a, &exp, &result)

	secp.field_pow(&result, &a, &exp, &p)
	expect_int_eq(t, &result, 1, "a^0 mod p should be 1")
}

@(test)
test_field_neg_basic :: proc(t: ^testing.T) {
	// -3 mod 7 = 4
	p := make_int(7)
	a := make_int(3)
	result: big.Int
	defer big.destroy(&p, &a, &result)

	err := secp.field_neg(&result, &a, &p)
	testing.expect(t, err == .None, "field_neg should succeed")
	expect_int_eq(t, &result, 4, "-3 mod 7 should be 4")
}

@(test)
test_field_neg_zero :: proc(t: ^testing.T) {
	// -0 mod 7 = 0
	p := make_int(7)
	a := make_int(0)
	result: big.Int
	defer big.destroy(&p, &a, &result)

	secp.field_neg(&result, &a, &p)
	is_z, _ := big.is_zero(&result)
	testing.expect(t, is_z, "-0 mod p should be 0")
}

@(test)
test_field_inv_verify_with_secp256k1_p :: proc(t: ^testing.T) {
	// a * a^(-1) mod p = 1 (using actual secp256k1 p)
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	a := make_hex("DEADBEEF1234567890ABCDEF")
	inv, product: big.Int
	defer big.destroy(&a, &inv, &product)

	err := secp.field_inv(&inv, &a, &params.p)
	testing.expect(t, err == .None, "field_inv should succeed with secp256k1 p")

	secp.field_mul(&product, &a, &inv, &params.p)
	expect_int_eq(t, &product, 1, "a * a^(-1) mod p should be 1")
}

@(test)
test_field_add_wraps_at_p :: proc(t: ^testing.T) {
	// (p-1) + 1 mod p = 0
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	p_minus_1, one, result: big.Int
	defer big.destroy(&p_minus_1, &one, &result)

	big.set(&one, 1)
	big.sub(&p_minus_1, &params.p, &one)

	secp.field_add(&result, &p_minus_1, &one, &params.p)
	is_z, _ := big.is_zero(&result)
	testing.expect(t, is_z, "(p-1) + 1 mod p should be 0")
}

@(test)
test_field_sub_self :: proc(t: ^testing.T) {
	// a - a mod p = 0
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	a := make_hex("123456789ABCDEF0")
	result: big.Int
	defer big.destroy(&a, &result)

	secp.field_sub(&result, &a, &a, &params.p)
	is_z, _ := big.is_zero(&result)
	testing.expect(t, is_z, "a - a mod p should be 0")
}
