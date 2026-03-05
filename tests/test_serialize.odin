package secp256k1_tests

import "core:math/big"
import "core:testing"
import secp "../secp256k1"

@(test)
test_serialize_uncompressed_g :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	buf: [65]u8
	err := secp.serialize_point_uncompressed(&buf, &g, &params)
	testing.expect(t, err == .None, "serialize uncompressed should succeed")
	testing.expect(t, buf[0] == 0x04, "uncompressed prefix should be 0x04")
}

@(test)
test_serialize_compressed_g :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	buf: [33]u8
	err := secp.serialize_point_compressed(&buf, &g, &params)
	testing.expect(t, err == .None, "serialize compressed should succeed")

	// Gy is even (ends in B8), so prefix should be 0x02
	testing.expect(t, buf[0] == 0x02, "G has even y, prefix should be 0x02")
}

@(test)
test_serialize_compressed_odd_y :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	// 3G has odd y (ends in 72)
	pt := make_point(
		"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	)
	defer secp.point_destroy(&pt)

	buf: [33]u8
	err := secp.serialize_point_compressed(&buf, &pt, &params)
	testing.expect(t, err == .None, "serialize compressed should succeed")
	testing.expect(t, buf[0] == 0x02, "3G has even y (last byte 0x72), prefix should be 0x02")
}

@(test)
test_deserialize_uncompressed_roundtrip :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	// Serialize
	buf: [65]u8
	secp.serialize_point_uncompressed(&buf, &g, &params)

	// Deserialize
	result: secp.Point
	defer secp.point_destroy(&result)
	err := secp.deserialize_point(&result, buf[:], &params)
	testing.expect(t, err == .None, "deserialize uncompressed should succeed")
	expect_point_eq(t, &result, &g, "roundtrip should preserve point")
}

@(test)
test_deserialize_compressed_roundtrip :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	g := make_point(secp.GX_HEX, secp.GY_HEX)
	defer secp.point_destroy(&g)

	// Serialize compressed
	buf: [33]u8
	secp.serialize_point_compressed(&buf, &g, &params)

	// Deserialize
	result: secp.Point
	defer secp.point_destroy(&result)
	err := secp.deserialize_point(&result, buf[:], &params)
	testing.expect(t, err == .None, "deserialize compressed should succeed")
	expect_point_eq(t, &result, &g, "compressed roundtrip should preserve point")
}

@(test)
test_deserialize_compressed_2g_roundtrip :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	pt := make_point(
		"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	)
	defer secp.point_destroy(&pt)

	buf: [33]u8
	secp.serialize_point_compressed(&buf, &pt, &params)

	result: secp.Point
	defer secp.point_destroy(&result)
	err := secp.deserialize_point(&result, buf[:], &params)
	testing.expect(t, err == .None, "deserialize compressed 2G should succeed")
	expect_point_eq(t, &result, &pt, "compressed 2G roundtrip should preserve point")
}

@(test)
test_deserialize_invalid_prefix :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	bad_data: [33]u8
	bad_data[0] = 0x05 // invalid prefix
	result: secp.Point
	defer secp.point_destroy(&result)

	err := secp.deserialize_point(&result, bad_data[:], &params)
	testing.expect(t, err == .Invalid_Format, "should reject invalid prefix")
}

@(test)
test_deserialize_wrong_length :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	bad_data: [10]u8
	bad_data[0] = 0x04
	result: secp.Point
	defer secp.point_destroy(&result)

	err := secp.deserialize_point(&result, bad_data[:], &params)
	testing.expect(t, err == .Invalid_Length, "should reject wrong length for uncompressed")
}

@(test)
test_serialize_infinity_fails :: proc(t: ^testing.T) {
	params: secp.Curve_Params
	secp.init_curve_params(&params)
	defer secp.destroy_curve_params(&params)

	inf := secp.point_infinity()
	defer secp.point_destroy(&inf)

	buf_u: [65]u8
	err_u := secp.serialize_point_uncompressed(&buf_u, &inf, &params)
	testing.expect(t, err_u == .Invalid_Format, "should not serialize infinity uncompressed")

	buf_c: [33]u8
	err_c := secp.serialize_point_compressed(&buf_c, &inf, &params)
	testing.expect(t, err_c == .Invalid_Format, "should not serialize infinity compressed")
}
