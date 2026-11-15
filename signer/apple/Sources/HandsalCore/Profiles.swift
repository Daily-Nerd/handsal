/// The two profiles (CF-01, GP-07, GP-18): their hashes and the fixture kid list.
///
/// A profile hash is the hashstr of the canonical bytes of `{"core": <core manifest>, "kind": ...}`.
/// The core manifest and the fixture kid list are copies of repository files (the signer has no
/// JSON reader), so `ProfileTests` hashes the real files and fails when a copy is stale. Update
/// the two tables below when that test says so.
public struct Profiles: Sendable {
    public let production: String
    public let fixture: String
    public let fixtureKids: Set<String>

    public static let coreManifest: [String: String] = [
        "conformance/CONTRACT.md": "uEiChxwv2U0E9pE4O7o25fBjTQqvvrWoa-9WXq_-kMZeplQ",
        "conformance/fixtures/fixture-kids.json": "uEiAA2Ut1j1_YVg4vT24wa7AyTSI_vcw746yVgZtZ7EDI6w",
        "conformance/fixtures/keys.json": "uEiBTiMULo39V4bRDRi3Ub4BtQBxK0PVHKjYu0K5uhaorUg",
        "spec/profile-interfaces.md": "uEiALewAj02jLK6G1bCmZvQfgoAv8xJQyhko5ZI6VRxyDZQ",
        "spec/profile-part3.md": "uEiAN3vZyisJ_rhqs8PvjCTK3WOgRzSKz8klEevfERDdhAA",
        "spec/profile.md": "uEiDhHdRAf0tAvsrNBhRZRvWjewpdJd0fEIfPAqKDIp5dRg",
        "spec/registry.json": "uEiDXblUNp-OOInT2aWu5fHApEBhgCzdnOnZJDY-hkbwDeA",
    ]

    private static let fixtureKidList: Set<String> = [
        "04kif0rHiJMrEMpswt7Oz4GwcBBVfHWLqibEm_iKGFw", "1sDZS3uxv-Uv1btMhME1K1mVFsY_8IQRyjhsZ08lCgw",
        "6qN-iqyrsO9JFfMvfvXgSrTp3j6854R6bhrBW-lER3s", "CDrZnrBvzLPTeAPEw_baQqAz80c0rBAeqH4JAV6DbrE",
        "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI", "LCFRCp5jqzyR6ucB2jkQ1_tLrG2ov9H6UJ_jjnXqiM0",
        "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY", "SQuEiTt6F8UAWadKzIW5a2TFXoKwzzzEw758iV3Y7Lc",
        "TYx7gcpoVR6xfbi8Xr27veF_PM6tIthU6kOak5nvHBM", "bsPcoKwcMCjtGVOdhUotGE853GWptmdCaOtjEQrBG1s",
        "hpdEKF8aS-kmoBoDRnTRYJ0W8mpf9bGBA1oQ_buFYaA", "j5-D2wrnMtT9G_u8Cr8zKTdrxQy1uo0qaER3KBzmaZk",
        "mtKGrRE1qPZnGdTaFLCaZEVPxUXvUIZle_dS5PWItaQ", "of1nfC9_5wXxtcfDSmTgYFT49CAxpCmIXc3kq68AXuM",
        "pOaW_J5K8Ip7oy1_icIVm6fSDHCW-qZcpaaylZoyA_8", "q0KvzQLXjrxsiKQsS2evdDgXk3VLeogpmGzTSXHYCd4",
        "ypEDa7uErEI86ScpKG6qPxsN9x0Ut83LiSBtxYcKHeQ", "zMO7_LbnDpMEfp8KIfuR9AcGobxqBjNTIUipQe0dsTc",
    ]

    private static func hash(_ kind: String) -> String {
        let manifest = JValue.object(coreManifest.mapValues { .string($0) })
        guard let bytes = try? Emit.subset(.object(["core": manifest, "kind": .string(kind)])) else {
            fatalError("the core manifest is not in the canonical subset")
        }
        return Encoding.hashstr(bytes)
    }

    public static let standard = Profiles(production: hash("production"), fixture: hash("fixture"), fixtureKids: fixtureKidList)

    /// `"production"`, `"fixture"` or nil for a value that is no implemented profile.
    public func kind(_ profile: String) -> String? {
        if profile == production { return "production" }
        if profile == fixture { return "fixture" }
        return nil
    }

    public func isFixtureKid(_ kid: String) -> Bool { fixtureKids.contains(kid) }
}
