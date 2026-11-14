/// Field forms of section 2.2: the single owner of what each named form accepts. ASCII only, no
/// regular expression engine, no locale.
public enum Forms {
    private static func ascii(_ s: String) -> [UInt8]? {
        let bytes = Array(s.utf8)
        return bytes.allSatisfy { $0 < 0x80 } ? bytes : nil
    }

    private static func lower(_ b: UInt8) -> Bool { b >= 0x61 && b <= 0x7A }
    private static func digit(_ b: UInt8) -> Bool { b >= 0x30 && b <= 0x39 }

    /// `[a-z0-9][a-z0-9-]{min-1,max-1}`
    private static func slug(_ s: String, min: Int, max: Int, letterFirst: Bool) -> Bool {
        guard let b = ascii(s), b.count >= min, b.count <= max else { return false }
        let first = b[0]
        guard letterFirst ? lower(first) : (lower(first) || digit(first)) else { return false }
        return b.dropFirst().allSatisfy { lower($0) || digit($0) || $0 == 0x2D }
    }

    public static func isMemberId(_ s: String) -> Bool { slug(s, min: 2, max: 32, letterFirst: false) }
    public static func isRoleId(_ s: String) -> Bool { slug(s, min: 1, max: 32, letterFirst: true) }
    public static func isClassId(_ s: String) -> Bool { isRoleId(s) }
    public static func isRequestId(_ s: String) -> Bool { slug(s, min: 8, max: 36, letterFirst: false) }
    public static func isRecordId(_ s: String) -> Bool { slug(s, min: 2, max: 32, letterFirst: false) }
    /// `[a-z][a-z0-9-]{1,31}`, the consumer a decision is for (VR-18).
    public static func isConsumerId(_ s: String) -> Bool { slug(s, min: 2, max: 32, letterFirst: true) }
    /// `[a-z0-9][a-z0-9-]{1,63}`, what a decision is about (VR-18).
    public static func isSubjectId(_ s: String) -> Bool { slug(s, min: 2, max: 64, letterFirst: false) }

    /// The longest `action` the grammar allows: the room line 1 of the render leaves for it (RN-03).
    public static let actionMax = 24

    /// Lowercase ASCII words separated by single spaces, 1 to 24 characters in all (VR-18).
    public static func isAction(_ s: String) -> Bool {
        guard let b = ascii(s), !b.isEmpty, b.count <= actionMax else { return false }
        var previousSpace = true   // a leading space is as wrong as a doubled one
        for byte in b {
            if byte == 0x20 {
                if previousSpace { return false }
                previousSpace = true
            } else if lower(byte) {
                previousSpace = false
            } else {
                return false
            }
        }
        return !previousSpace   // not a trailing space
    }

    private static func text(_ s: String, max: Int) -> Bool {
        let n = s.utf8.count
        return n >= 1 && n <= max && Text.isPlain(s)
    }

    public static func isLabel(_ s: String) -> Bool { text(s, max: 64) }
    public static func isOrgName(_ s: String) -> Bool { text(s, max: 24) }
    public static func isAnchor(_ s: String) -> Bool { text(s, max: 128) }

    /// `0` or `[1-9][0-9]{0,8}`
    public static func isDecimal(_ s: String) -> Bool {
        guard let b = ascii(s), !b.isEmpty, b.count <= 9, b.allSatisfy(digit) else { return false }
        return b.count == 1 || b[0] != 0x30
    }

    public static func isB64u32(_ s: String) -> Bool {
        s.utf8.count == 43 && (Encoding.base64urlDecode(s)?.count == 32)
    }

    public static func isHashstr(_ s: String) -> Bool { Encoding.isHashstr(s) }

    // MARK: time

    private static func isLeap(_ y: Int) -> Bool { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }

    private static func daysIn(_ y: Int, _ m: Int) -> Int {
        if m == 2 { return isLeap(y) ? 29 : 28 }
        return [4, 6, 9, 11].contains(m) ? 30 : 31
    }

    private static func fields(_ s: String) -> (Int, Int, Int, Int, Int, Int)? {
        let b = Array(s.utf8)
        guard b.count == 20, b[4] == 0x2D, b[7] == 0x2D, b[10] == 0x54, b[13] == 0x3A, b[16] == 0x3A,
              b[19] == 0x5A else { return nil }
        func num(_ range: Range<Int>) -> Int? {
            var out = 0
            for i in range {
                guard digit(b[i]) else { return nil }
                out = out * 10 + Int(b[i] - 0x30)
            }
            return out
        }
        guard let y = num(0..<4), let mo = num(5..<7), let d = num(8..<10),
              let h = num(11..<13), let mi = num(14..<16), let sec = num(17..<19) else { return nil }
        guard (1...12).contains(mo), d >= 1, d <= daysIn(y, mo), h <= 23, mi <= 59, sec <= 59 else { return nil }
        return (y, mo, d, h, mi, sec)
    }

    public static func isTime(_ s: String) -> Bool { fields(s) != nil }

    /// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
    private static func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int {
        let y = m <= 2 ? y0 - 1 : y0
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    private static func civilFromDays(_ z0: Int) -> (Int, Int, Int) {
        let z = z0 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (yoe + era * 400 + (m <= 2 ? 1 : 0), m, d)
    }

    /// Seconds since the epoch of a `time` value, or nil when `time` is not a `time`.
    public static func epochSeconds(_ time: String) -> Int? {
        guard let (y, mo, d, h, mi, s) = fields(time) else { return nil }
        return daysFromCivil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s
    }

    public static func time(epochSeconds: Int) -> String {
        let days = epochSeconds >= 0 ? epochSeconds / 86_400 : -((-epochSeconds + 86_399) / 86_400)
        let rest = epochSeconds - days * 86_400
        let (y, m, d) = civilFromDays(days)
        func pad(_ n: Int, _ width: Int) -> String {
            let s = String(n)
            return String(repeating: "0", count: max(0, width - s.count)) + s
        }
        return "\(pad(y, 4))-\(pad(m, 2))-\(pad(d, 2))T\(pad(rest / 3600, 2)):\(pad(rest % 3600 / 60, 2)):\(pad(rest % 60, 2))Z"
    }

    // MARK: hostname

    public static func isHostname(_ s: String) -> Bool {
        guard let b = ascii(s), !b.isEmpty, b.count <= 253 else { return false }
        return b.split(separator: 0x2E, omittingEmptySubsequences: false).allSatisfy { isLabel(Array($0)) }
            && !b.contains(where: { $0 == 0x20 })
    }

    private static func isLabel(_ label: [UInt8]) -> Bool {
        guard !label.isEmpty, label.count <= 63 else { return false }
        func alnum(_ b: UInt8) -> Bool { lower(b) || digit(b) }
        guard alnum(label[0]), alnum(label[label.count - 1]) else { return false }
        guard label.allSatisfy({ alnum($0) || $0 == 0x2D }) else { return false }
        if label.starts(with: Array("xn--".utf8)) {
            return punycodeDecodes(Array(label.dropFirst(4)))
        }
        return true
    }

    /// True when `input` (the part after `xn--`) is non-empty and decodes as Punycode (RFC 3492) to
    /// at least one code point.
    private static func punycodeDecodes(_ input: [UInt8]) -> Bool {
        guard !input.isEmpty else { return false }
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700
        var n = 128, i = 0, bias = 72
        var output: [UInt32] = []
        var position = 0
        if let delimiter = input.lastIndex(of: 0x2D) {
            output = input[..<delimiter].map { UInt32($0) }
            position = delimiter + 1
        }
        func digitValue(_ c: UInt8) -> Int? {
            if lower(c) { return Int(c - 0x61) }
            if digit(c) { return Int(c - 0x30) + 26 }
            return nil
        }
        func adapt(_ delta0: Int, _ points: Int, _ first: Bool) -> Int {
            var delta = first ? delta0 / damp : delta0 / 2
            delta += delta / points
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 { delta /= base - tmin; k += base }
            return k + (base - tmin + 1) * delta / (delta + skew)
        }
        while position < input.count {
            let old = i
            var w = 1
            var k = base
            while true {
                guard position < input.count, let d = digitValue(input[position]) else { return false }
                position += 1
                let (product, o1) = d.multipliedReportingOverflow(by: w)
                let (sum, o2) = i.addingReportingOverflow(product)
                if o1 || o2 { return false }
                i = sum
                let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                if d < t { break }
                let (nw, o3) = w.multipliedReportingOverflow(by: base - t)
                if o3 { return false }
                w = nw
                k += base
            }
            bias = adapt(i - old, output.count + 1, old == 0)
            n += i / (output.count + 1)
            i %= output.count + 1
            guard n <= 0x10FFFF, UnicodeScalar(UInt32(n)) != nil else { return false }
            output.insert(UInt32(n), at: i)
            i += 1
        }
        return !output.isEmpty
    }
}
