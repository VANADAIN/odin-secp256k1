package secp256k1

import "core:math/big"

// Affine point on secp256k1. Infinity represented by is_inf flag.
Point :: struct {
	x:      big.Int,
	y:      big.Int,
	is_inf: bool,
}

Point_Error :: enum {
	None,
	Field_Error,
}

point_infinity :: proc() -> Point {
	return Point{is_inf = true}
}

point_is_infinity :: proc(p: ^Point) -> bool {
	return p.is_inf
}

point_destroy :: proc {
	point_destroy_one,
	point_destroy_many,
}

point_destroy_one :: proc(p: ^Point) {
	big.destroy(&p.x, &p.y)
}

point_destroy_many :: proc(points: ..^Point) {
	for p in points {
		big.destroy(&p.x, &p.y)
	}
}

// Copy src point into dst
point_copy :: proc(dst, src: ^Point) {
	dst.is_inf = src.is_inf
	big.set(&dst.x, &src.x)
	big.set(&dst.y, &src.y)
}

// result = P + Q on secp256k1
// Uses the standard affine addition formulas.
point_add :: proc(result, p, q: ^Point, params: ^Curve_Params) -> Point_Error {
	// O + Q = Q
	if point_is_infinity(p) {
		point_copy(result, q)
		return .None
	}
	// P + O = P
	if point_is_infinity(q) {
		point_copy(result, p)
		return .None
	}

	eq_x, _ := big.equals(&p.x, &q.x)
	if eq_x {
		eq_y, _ := big.equals(&p.y, &q.y)
		if eq_y {
			// P == Q => use doubling
			return point_double(result, p, params)
		}
		// Same x, different y => P + (-P) = O
		result.is_inf = true
		return .None
	}

	// General case: P != Q, different x
	// slope = (q.y - p.y) / (q.x - p.x) mod p
	dy, dx, dx_inv, slope, x3, y3: big.Int
	defer big.destroy(&dy, &dx, &dx_inv, &slope, &x3, &y3)
	fp := &params.p

	if field_sub(&dy, &q.y, &p.y, fp) != .None do return .Field_Error
	if field_sub(&dx, &q.x, &p.x, fp) != .None do return .Field_Error
	if field_inv(&dx_inv, &dx, fp) != .None do return .Field_Error
	if field_mul(&slope, &dy, &dx_inv, fp) != .None do return .Field_Error

	// x3 = slope² - p.x - q.x  mod p
	if big.sqrmod(&x3, &slope, fp) != nil do return .Field_Error
	if field_sub(&x3, &x3, &p.x, fp) != .None do return .Field_Error
	if field_sub(&x3, &x3, &q.x, fp) != .None do return .Field_Error

	// y3 = slope * (p.x - x3) - p.y  mod p
	diff_a: big.Int
	defer big.destroy(&diff_a)
	if field_sub(&diff_a, &p.x, &x3, fp) != .None do return .Field_Error
	if field_mul(&y3, &slope, &diff_a, fp) != .None do return .Field_Error
	if field_sub(&y3, &y3, &p.y, fp) != .None do return .Field_Error

	result.is_inf = false
	big.set(&result.x, &x3)
	big.set(&result.y, &y3)
	return .None
}

// result = 2P on secp256k1
// Uses the tangent-line doubling formula.
point_double :: proc(result, p: ^Point, params: ^Curve_Params) -> Point_Error {
	if point_is_infinity(p) {
		result.is_inf = true
		return .None
	}

	// If y == 0, tangent is vertical => result is O
	y_zero, _ := big.is_zero(&p.y)
	if y_zero {
		result.is_inf = true
		return .None
	}

	// For secp256k1 (a=0): slope = 3x² / 2y  mod p
	x_sq, num, denom, denom_inv, slope, x3, y3: big.Int
	defer big.destroy(&x_sq, &num, &denom, &denom_inv, &slope, &x3, &y3)
	fp := &params.p

	// num = 3 * x²
	if big.sqrmod(&x_sq, &p.x, fp) != nil do return .Field_Error
	three: big.Int
	defer big.destroy(&three)
	big.set(&three, 3)
	if field_mul(&num, &three, &x_sq, fp) != .None do return .Field_Error

	// denom = 2y
	two: big.Int
	defer big.destroy(&two)
	big.set(&two, 2)
	if field_mul(&denom, &two, &p.y, fp) != .None do return .Field_Error

	if field_inv(&denom_inv, &denom, fp) != .None do return .Field_Error
	if field_mul(&slope, &num, &denom_inv, fp) != .None do return .Field_Error

	// x3 = slope² - 2x  mod p
	if big.sqrmod(&x3, &slope, fp) != nil do return .Field_Error
	if field_sub(&x3, &x3, &p.x, fp) != .None do return .Field_Error
	if field_sub(&x3, &x3, &p.x, fp) != .None do return .Field_Error

	// y3 = slope * (x - x3) - y  mod p
	diff_d: big.Int
	defer big.destroy(&diff_d)
	if field_sub(&diff_d, &p.x, &x3, fp) != .None do return .Field_Error
	if field_mul(&y3, &slope, &diff_d, fp) != .None do return .Field_Error
	if field_sub(&y3, &y3, &p.y, fp) != .None do return .Field_Error

	result.is_inf = false
	big.set(&result.x, &x3)
	big.set(&result.y, &y3)
	return .None
}
