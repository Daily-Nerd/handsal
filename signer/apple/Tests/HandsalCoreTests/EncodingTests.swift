import HandsalCore
import Testing

@Suite("encodings and field forms (section 2)")
struct EncodingTests {
    // Values below come from the Python reference (checker `encoding`) and the fixture keys.
    @Test func hashstrOfEmptyAndOfBytes() {
        #expect(Encoding.emptyHash == "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ")
        #expect(Encoding.hashstr(Array("deploy v2".utf8)) == "uEiCwmAdoEBagBdcJhxJqKaPD78wSAoyQmX3fj-_8GlSwRQ")
        #expect(Encoding.hashstr([]) == Encoding.emptyHash)
    }

    @Test func thumbprintOfFixtureKey() {
        #expect(Encoding.thumbprint(x: "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM",
                                    y: "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw")
            == "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI")
    }

    @Test func base64urlRoundTripsAndRefusesNonCanonical() {
        #expect(Encoding.base64url([0xFB, 0xFF]) == "-_8")
        #expect(Encoding.base64urlDecode("-_8") == [0xFB, 0xFF])
        #expect(Encoding.base64urlDecode("-_9") == nil)      // spare bits set
        #expect(Encoding.base64urlDecode("-_8=") == nil)     // padding
        #expect(Encoding.base64urlDecode("a") == nil)        // impossible length
        #expect(Encoding.base64urlDecode("+/8") == nil)      // standard alphabet
        #expect(Encoding.base64urlDecode("") == [])
    }

    @Test func standardBase64IsPaddedAndCanonical() {
        #expect(Encoding.base64Decode("ZGVwbG95IHYy") == Array("deploy v2".utf8))
        #expect(Encoding.base64Decode("YQ==") == [0x61])
        #expect(Encoding.base64Decode("") == [])
        #expect(Encoding.base64Decode("YQ") == nil)          // padding required
        #expect(Encoding.base64Decode("YR==") == nil)        // spare bits set
        #expect(Encoding.base64Decode("-_8=") == nil)        // url alphabet
        #expect(Encoding.base64Decode("YQ==\n") == nil)
    }

    @Test func hashstrForm() {
        #expect(Encoding.isHashstr(Encoding.emptyHash))
        #expect(!Encoding.isHashstr("uEi"))
        #expect(!Encoding.isHashstr(String(Encoding.emptyHash.dropLast()) + "R"))   // trailing bits
        #expect(!Encoding.isHashstr("x" + Encoding.emptyHash.dropFirst()))
    }

    @Test(arguments: ["alice", "a1", "a-b", "0a", String(repeating: "a", count: 32)])
    func goodMemberIds(id: String) { #expect(Forms.isMemberId(id)) }

    @Test(arguments: ["a", "-a", "A1", "a_b", "", String(repeating: "a", count: 33)])
    func badMemberIds(id: String) { #expect(!Forms.isMemberId(id)) }

    @Test func otherIdentifierForms() {
        #expect(Forms.isRoleId("m") && Forms.isRoleId("maintainer") && !Forms.isRoleId("1a") && !Forms.isRoleId(""))
        #expect(Forms.isRequestId("req-0001") && !Forms.isRequestId("req-001"))
        #expect(!Forms.isRequestId(String(repeating: "a", count: 37)) && Forms.isRequestId(String(repeating: "a", count: 36)))
        #expect(Forms.isRecordId("rec-0001") && !Forms.isRecordId("r") && !Forms.isRecordId("-r"))
    }

    @Test func textForms() {
        #expect(Forms.isLabel("alice se-bio") && !Forms.isLabel("") && !Forms.isLabel("a\"b") && !Forms.isLabel("a\\b"))
        #expect(Forms.isLabel(String(repeating: "x", count: 64)) && !Forms.isLabel(String(repeating: "x", count: 65)))
        #expect(!Forms.isLabel("caf\u{E9}") && !Forms.isLabel("a\u{7F}"))
        #expect(Forms.isOrgName(String(repeating: "x", count: 24)) && !Forms.isOrgName(String(repeating: "x", count: 25)))
        #expect(Forms.isAnchor(String(repeating: "x", count: 128)) && !Forms.isAnchor(String(repeating: "x", count: 129)))
    }

    @Test func decimalStrings() {
        for good in ["0", "7", "10", "123456789"] { #expect(Forms.isDecimal(good)) }
        for bad in ["", "01", "-1", "1234567890", "1.0", "+1", " 1"] { #expect(!Forms.isDecimal(bad)) }
    }

    @Test func timeForm() {
        #expect(Forms.isTime("2026-11-08T11:59:00Z") && Forms.isTime("2024-02-29T00:00:59Z"))
        for bad in ["2026-11-08T11:59:00", "2026-13-08T11:59:00Z", "2025-02-29T00:00:00Z", "2026-11-08T24:00:00Z",
                    "2026-11-08T11:60:00Z", "2026-11-08T11:59:60Z", "2026-11-08t11:59:00Z", "2026-1-08T11:59:00Z"] {
            #expect(!Forms.isTime(bad))
        }
    }

    @Test func epochSecondsRoundTrip() {
        #expect(Forms.epochSeconds("1970-01-01T00:00:00Z") == 0)
        #expect(Forms.epochSeconds("2026-11-08T11:59:00Z") == 1_794_139_140)
        #expect(Forms.time(epochSeconds: 1_794_139_140) == "2026-11-08T11:59:00Z")
        #expect(Forms.time(epochSeconds: 0) == "1970-01-01T00:00:00Z")
        #expect(Forms.time(epochSeconds: 1_794_139_140 + 2_592_000) == "2026-12-08T11:59:00Z")
        #expect(Forms.epochSeconds("bad") == nil)
    }

    @Test func hostnames() {
        for good in ["r.example", "a", "a-b.example", "xn--bcher-kva.example", String(repeating: "a", count: 63) + ".io"] {
            #expect(Forms.isHostname(good), "\(good)")
        }
        for bad in ["", "R.example", "-a.example", "a-.example", "a..b", "a.", "a:80", "a b", "a_b",
                    String(repeating: "a", count: 64) + ".io", "xn--", "xn--a-", "xn--\u{E9}"] {
            #expect(!Forms.isHostname(bad), "\(bad)")
        }
        let host253 = [String(repeating: "a", count: 63), String(repeating: "b", count: 63),
                       String(repeating: "c", count: 63), String(repeating: "d", count: 61)].joined(separator: ".")
        #expect(host253.count == 253 && Forms.isHostname(host253))
        #expect(!Forms.isHostname(host253 + "e"))
    }

    @Test func b64u32() {
        #expect(Forms.isB64u32("FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM"))
        #expect(!Forms.isB64u32("FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5w"))
        #expect(!Forms.isB64u32("FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wN"))   // spare bits
    }
}
