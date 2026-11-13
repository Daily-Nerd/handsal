import HandsalCore
import Testing

private func hex(_ text: String) -> [UInt8] { Vector.decodeHex(text) }

/// VR-04 and SG-06: the low-S rule, with n and n/2 written out in the test and not taken from
/// the code under test.
@Suite("low-S normalization (SG-06, VR-04)")
struct SignatureTests {
    private let r = [UInt8](repeating: 0x11, count: 32)
    private let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    private let half = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")

    private func s32(_ low: UInt8) -> [UInt8] { [UInt8](repeating: 0, count: 31) + [low] }

    @Test func aLowSIsLeftAlone() throws {
        for s in [s32(1), s32(200), half] {
            #expect(try Signature.lowS(r + s) == r + s)
        }
    }

    @Test func aHighSBecomesNMinusS() throws {
        // n - 1 is the highest S; n - 1 -> 1
        var top = n; top[31] -= 1
        #expect(try Signature.lowS(r + top) == r + s32(1))
        // (n+1)/2 = half + 1 is the lowest high S; n - (half + 1) = half
        var lowestHigh = half; lowestHigh[31] += 1
        #expect(try Signature.lowS(r + lowestHigh) == r + half)
        // a mid high value, checked by adding back: (n - s) + s == n
        let s = hex("deadbeef00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        let flipped = try Signature.lowS(r + s)
        #expect(Array(flipped[0..<32]) == r)
        #expect(sum(Array(flipped[32..<64]), s) == n)
    }

    @Test func rIsNeverTouched() throws {
        let other = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
        var top = n; top[31] -= 1
        #expect(Array(try Signature.lowS(other + top)[0..<32]) == other)
    }

    @Test func onlySixtyFourBytesAreASignature() {
        for size in [0, 63, 65, 96] {
            #expect(throws: Refusal("internal")) { try Signature.lowS([UInt8](repeating: 1, count: size)) }
        }
    }

    @Test func sEqualToZeroOrNIsInternal() {
        #expect(throws: Refusal("internal")) { try Signature.lowS(r + [UInt8](repeating: 0, count: 32)) }
        #expect(throws: Refusal("internal")) { try Signature.lowS(r + n) }
    }

    private func sum(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var carry = 0
        for index in stride(from: 31, through: 0, by: -1) {
            let value = Int(a[index]) + Int(b[index]) + carry
            out[index] = UInt8(value & 255)
            carry = value >> 8
        }
        return out
    }
}
