import HandsalCore
import Testing

private let bs = String(UnicodeScalar(0x5C))

private func parse(_ text: String, maxSize: Int = 16384) -> Result<JValue, SubsetFailure> {
    Subset.parse(Array(text.utf8), maxSize: maxSize)
}

private func nested(_ depth: Int) -> String {
    String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
}

@Suite("canonical subset recognizer (ACT-04)")
struct SubsetTests {
    @Test func readsObjectsArraysStringsAndNull() {
        #expect(parse(#"{"a":"b"}"#) == .success(.object(["a": .string("b")])))
        #expect(parse(#"{"a":[null,"x"],"b":{}}"#)
            == .success(.object(["a": .array([.null, .string("x")]), "b": .object([:])])))
    }

    @Test func anyRootKindIsGrammar() {
        #expect(parse("null") == .success(.null))
        #expect(parse("[]") == .success(.array([])))
        #expect(parse(#""a/b""#) == .success(.string("a/b")))
    }

    @Test(arguments: [
        #"{"a":1}"#, #"{"a":true}"#, #"{"a":false}"#, #"{"a": "b"}"#, #"{"a":"b"} "#, #"{"a":"b"}x"#,
        #"{"b":"1","a":"2"}"#, #"{"a":"1","a":"2"}"#, #"{"a":"\"" }"#, "{\"a\":\"" + bs + "u0041\"}", #"{"a":"\/"}"#,
        #"{"é":"1"}"#, #"{"a":"é"}"#, "{\"a\":\"x\ny\"}", "{\"a\":\"\u{7F}\"}", "{\"a\":\"\u{2028}\"}",
        "\u{FEFF}{}", "", "{", #"{"a"}"#, #"{"a":}"#, #"["a",]"#, "nul", "NULL",
    ])
    func refusesWhatIsOutsideTheGrammar(text: String) {
        #expect(parse(text) == .failure(.notCanonical))
    }

    @Test func refusesInvalidUtf8() {
        #expect(Subset.parse([0x22, 0xFF, 0x22], maxSize: 16384) == .failure(.notCanonical))
        #expect(Subset.parse([0x22, 0xC3, 0xA9, 0x22], maxSize: 16384) == .failure(.notCanonical))
    }

    @Test func nestingIsBoundedAtEight() {
        #expect(parse(nested(8)) != .failure(.notCanonical))
        #expect(parse(nested(9)) == .failure(.notCanonical))
        // A hostile deep input stops at the bound; it never recurses to the end.
        #expect(parse(nested(200_000), maxSize: 1 << 24) == .failure(.notCanonical))
    }

    @Test func sizeIsCheckedFirstAgainstTheCallersBound() {
        let big = "[" + String(repeating: "null,", count: 5) + "null]"
        #expect(parse(big, maxSize: big.utf8.count) != .failure(.tooLarge))
        #expect(parse(big, maxSize: big.utf8.count - 1) == .failure(.tooLarge))
        // Over the bound and malformed: the size wins.
        #expect(parse("{{{{", maxSize: 3) == .failure(.tooLarge))
    }
}
