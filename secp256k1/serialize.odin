package secp256k1

import "core:math/big"
import "core:mem"

// Point serialization formats for secp256k1 public keys.

Serialize_Error :: enum {
	None,
	Invalid_Format,
	Invalid_Length,
	Not_On_Curve,
	Field_Error,
	Big_Error,
}

// Serialize a point in uncompressed format (65 bytes): 0x04 || x || y
serialize_point_uncompressed :: proc(buf: ^[65]u8, pt: ^Point, params: ^Curve_Params) -> Serialize_Error {
	if point_is_infinity(pt) do return .Invalid_Format

	buf[0] = 0x04
	if big.int_to_bytes_big(&pt.x, buf[1:33]) != nil do return .Big_Error
	if big.int_to_bytes_big(&pt.y, buf[33:65]) != nil do return .Big_Error
	return .None
}

// Serialize a point in compressed format (33 bytes): prefix || x
// prefix = 0x02 if y is even, 0x03 if y is odd
serialize_point_compressed :: proc(buf: ^[33]u8, pt: ^Point, params: ^Curve_Params) -> Serialize_Error {
	if point_is_infinity(pt) do return .Invalid_Format

	// Check if y is odd (bit 0)
	bit, berr := big.int_bitfield_extract_single(&pt.y, 0)
	if berr != nil do return .Big_Error

	buf[0] = 0x02 + u8(bit) // 0x02 if even, 0x03 if odd
	if big.int_to_bytes_big(&pt.x, buf[1:33]) != nil do return .Big_Error
	return .None
}

// Deserialize a point from uncompressed (65 bytes) or compressed (33 bytes) format.
deserialize_point :: proc(pt: ^Point, data: []u8, params: ^Curve_Params) -> Serialize_Error {
	if len(data) == 0 do return .Invalid_Length

	switch data[0] {
	case 0x04:
		return _deserialize_uncompressed(pt, data, params)
	case 0x02, 0x03:
		return _deserialize_compressed(pt, data, params)
	case:
		return .Invalid_Format
	}
}

_deserialize_uncompressed :: proc(pt: ^Point, data: []u8, params: ^Curve_Params) -> Serialize_Error {
	if len(data) != 65 do return .Invalid_Length

	if big.int_from_bytes_big(&pt.x, data[1:33]) != nil do return .Big_Error
	if big.int_from_bytes_big(&pt.y, data[33:65]) != nil do return .Big_Error
	pt.is_inf = false

	if !_point_on_curve(pt, params) do return .Not_On_Curve
	return .None
}

_deserialize_compressed :: proc(pt: ^Point, data: []u8, params: ^Curve_Params) -> Serialize_Error {
	if len(data) != 33 do return .Invalid_Length

	if big.int_from_bytes_big(&pt.x, data[1:33]) != nil do return .Big_Error

	// Compute y² = x³ + 7 mod p
	y_sq, x3: big.Int
	defer big.destroy(&y_sq, &x3)
	fp := &params.p

	if big.sqrmod(&x3, &pt.x, fp) != nil do return .Big_Error
	if big.mulmod(&x3, &x3, &pt.x, fp) != nil do return .Big_Error
	if big.addmod(&y_sq, &x3, &params.b, fp) != nil do return .Big_Error

	// Compute y = y_sq^((p+1)/4) mod p
	// This works because p ≡ 3 (mod 4) for secp256k1
	exp, one: big.Int
	defer big.destroy(&exp, &one)
	big.set(&one, 1)
	if big.add(&exp, fp, &one) != nil do return .Big_Error

	four: big.Int
	defer big.destroy(&four)
	big.set(&four, 4)
	if big.div(&exp, &exp, &four) != nil do return .Big_Error

	if field_pow(&pt.y, &y_sq, &exp, fp) != .None do return .Field_Error

	// Verify: y² mod p == y_sq
	check: big.Int
	defer big.destroy(&check)
	if big.sqrmod(&check, &pt.y, fp) != nil do return .Big_Error
	eq, _ := big.equals(&check, &y_sq)
	if !eq do return .Not_On_Curve

	// Choose correct y parity based on prefix
	is_odd: bool
	bit, berr := big.int_bitfield_extract_single(&pt.y, 0)
	if berr != nil do return .Big_Error
	is_odd = bit == 1

	want_odd := data[0] == 0x03
	if is_odd != want_odd {
		// y = p - y
		if big.sub(&pt.y, fp, &pt.y) != nil do return .Big_Error
	}

	pt.is_inf = false
	return .None
}

// Check if a point is on the curve: y² = x³ + 7 (mod p)
_point_on_curve :: proc(pt: ^Point, params: ^Curve_Params) -> bool {
	if point_is_infinity(pt) do return true

	lhs, rhs, x3: big.Int
	defer big.destroy(&lhs, &rhs, &x3)
	fp := &params.p

	big.sqrmod(&lhs, &pt.y, fp)
	big.sqrmod(&x3, &pt.x, fp)
	big.mulmod(&x3, &x3, &pt.x, fp)
	big.addmod(&rhs, &x3, &params.b, fp)

	eq, _ := big.equals(&lhs, &rhs)
	return eq
}
