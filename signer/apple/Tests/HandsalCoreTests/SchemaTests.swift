import Foundation
@testable import HandsalCore
import Testing

private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private let pointX = "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM"
private let pointY = "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw"
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"

private func point() -> JValue { .object(["x": .string(pointX), "y": .string(pointY)]) }

private func deviceAddBody() -> [String: JValue] {
    ["agree": point(), "class": .string("apple-se-bio"), "kid": .string(kid), "label": .string("alice2 se-bio"),
     "link_code_hash": .string(hs("link")), "person": .string("alice"), "sign": point()]
}

private func body(of method: String) -> SchemaNode {
    Registry.standard.methods[method]!.body
}

private func defects(_ method: String, _ value: JValue) -> [String] {
    Schema.defects(body(of: method), value, Registry.standard, code: "body_schema")
}

/// The registry in the repository is the one the profile hash covers. The Swift tables are a
/// second copy, so this test compares them with the file and fails when they drift. Every frozen
/// edition of the catalog carries the registry it was frozen with, and its table is compared the
/// same way: an edition whose table is missing or differs never ships green.
@Suite("registry tables match spec/registry.json")
struct RegistryGuardTests {
    static let doc: [String: JValue] = {
        let url = Vector.root.appendingPathComponent("spec/registry.json")
        guard case .object(let doc) = try! TestJSON.parse([UInt8](try! Data(contentsOf: url))) else { fatalError() }
        return doc
    }()

    /// Every way the method table of `registry` differs from the file `doc`.
    static func methodProblems(_ registry: Registry, _ doc: [String: JValue]) -> [String] {
        guard case .array(let entries)? = doc["methods"] else { return ["no methods"] }
        var out: [String] = []
        if registry.methods.count != entries.count { out.append("method count") }
        for entry in entries {
            guard case .object(let m) = entry, case .string(let name)? = m["method"] else { continue }
            guard let spec = registry.methods[name] else { out.append("missing \(name)"); continue }
            if m["head"] != .string(spec.head.rawValue) { out.append("\(name) head") }
            if m["inputs_hash"] != .string(spec.inputsHash) { out.append("\(name) inputs_hash") }
            if m["outputs_hash"] != .string(spec.outputsHash) { out.append("\(name) outputs_hash") }
            if m["act_extra_keys"] != .array(spec.actExtraKeys.map { .string($0) }) { out.append("\(name) extra keys") }
            if m["body"] != spec.body.registryJSON { out.append("\(name) body") }
        }
        return out
    }

    /// Every way the class tables of `registry` differ from the file `doc`.
    static func classProblems(_ registry: Registry, _ doc: [String: JValue]) -> [String] {
        guard case .array(let entries)? = doc["key_classes"], case .array(let fixture)? = doc["fixture_only"] else { return ["no classes"] }
        var out: [String] = []
        func check(_ list: [JValue], _ table: [String: ClassSpec], _ which: String) {
            if table.count != list.count { out.append("\(which) class count") }
            for entry in list {
                guard case .object(let c) = entry, case .string(let id)? = c["id"], let spec = table[id] else { out.append("\(which) class missing"); continue }
                if c["status"] != .string(spec.status) { out.append("\(id) status") }
                let uv: JValue = spec.userVerification.map { .string($0) } ?? .null
                if c["user_verification"] != uv { out.append("\(id) user_verification") }
            }
        }
        check(entries, registry.classes, "key")
        check(fixture, registry.fixtureOnly, "fixture")
        return out
    }

    /// Every way the constants and extra key types of `registry` differ from the file `doc`.
    static func constantProblems(_ registry: Registry, _ doc: [String: JValue]) -> [String] {
        guard case .object(let constants)? = doc["constants"] else { return ["no constants"] }
        var flat: [String: Int] = [:]
        func walk(_ prefix: String, _ value: JValue) {
            guard case .object(let o) = value else { return }
            for (key, child) in o {
                if case .string(let text) = child, let n = Int(text), ["value", "min", "max"].contains(key) || key.hasSuffix("_max") || key.hasSuffix("_bytes") || key.hasSuffix("_lines") {
                    flat[prefix + "." + key] = n
                } else { walk(prefix.isEmpty ? key : prefix + "." + key, child) }
            }
        }
        walk("", .object(constants))
        var out: [String] = flat.isEmpty ? ["no constants read"] : []
        for (path, n) in flat {
            // `NAME.value` is the registry's way of writing a plain constant `NAME`.
            let name = path.hasSuffix(".value") ? String(path.dropLast(6)) : path
            let key = name.hasPrefix(".") ? String(name.dropFirst()) : name
            if !registry.constantPaths.contains(key) || registry.number(key) != n { out.append(key) }
        }
        if case .object(let types)? = doc["act_extra_key_types"] {
            if registry.actExtraKeyTypes.count != types.count { out.append("act_extra_key_types count") }
            for (key, value) in types where value != .string(registry.actExtraKeyTypes[key]?.rawValue ?? "?") { out.append(key) }
        }
        return out
    }

    static func problems(_ registry: Registry, _ doc: [String: JValue]) -> [String] {
        methodProblems(registry, doc) + classProblems(registry, doc) + constantProblems(registry, doc)
    }

    /// Every way the frozen edition `block` and its table disagree: the table against the registry the block carries, and
    /// the two hashes against the manifest the block carries. The table of the live core is `Registry.standard`.
    static func problems(of block: FrozenEdition) -> [String] {
        var out: [String] = []
        let table = Registry.resolve(for: block)
        guard case .object(let frozen)? = try? TestJSON.parse(Array(block.registryJSON.utf8)) else {
            return ["\(block.label): the registry of the block is not an object"]
        }
        if let table { out += problems(table, frozen).map { "\(block.label): \($0)" } } else { out.append("\(block.label): no evaluation table") }
        if block.production != Profiles.hash("production", block.coreManifest) { out.append("\(block.label): production hash") }
        if block.fixture != Profiles.hash("fixture", block.coreManifest) { out.append("\(block.label): fixture hash") }
        return out
    }

    @Test func methodTable() { #expect(Self.methodProblems(Registry.standard, Self.doc) == []) }

    @Test func classTable() { #expect(Self.classProblems(Registry.standard, Self.doc) == []) }

    @Test func constantsAndExtraKeyTypes() { #expect(Self.constantProblems(Registry.standard, Self.doc) == []) }

    /// One case per frozen edition block (none until the founding release freezes the first): its table is the one the
    /// block's own registry describes, and no table is kept for an edition that is not in the catalog.
    @Test func everyFrozenEditionBlockHasATableThatMatchesIt() {
        for block in Profiles.versions { #expect(Self.problems(of: block) == [], "\(block.label)") }
    }

    private static let liveRegistryHash = Profiles.coreManifest["spec/registry.json"] ?? ""

    /// A frozen block of an edition older than the live core: its own core manifest, with `registryHash` as the registry file hash.
    private static func olderBlock(registryHash: String) -> FrozenEdition {
        var manifest = Profiles.coreManifest
        manifest["spec/registry.json"] = registryHash
        manifest["spec/profile.md"] = Encoding.emptyHash
        return FrozenEdition(label: "edition-old", production: Profiles.hash("production", manifest), fixture: Profiles.hash("fixture", manifest),
                             coreManifest: manifest, fixtureKids: [], registryJSON: "{}")
    }

    /// The registry bytes did not change between editions, so the table did not either: a frozen block that is not the
    /// live core but carries the live registry hash is evaluated by `Registry.standard`.
    @Test func aFrozenBlockWithTheLiveRegistryHashGetsTheStandardTable() throws {
        let block = Self.olderBlock(registryHash: Self.liveRegistryHash)
        #expect(block.production != Profiles.live.production)
        let table = try #require(Registry.resolve(for: block, liveRegistryHash: Self.liveRegistryHash, tables: [:]))
        #expect(Self.problems(table, Self.doc) == [])
        // a table kept under the live hash does not take the place of the live one
        let extra = Registry.standard.addingClass(ClassSpec(id: "later-hw", status: "active", userVerification: nil))
        let kept = try #require(Registry.resolve(for: block, liveRegistryHash: Self.liveRegistryHash, tables: [Self.liveRegistryHash: extra]))
        #expect(Self.problems(kept, Self.doc) == [])
    }

    /// A registry that is not the live one is looked up by its hash, whatever the edition label.
    @Test func aFrozenBlockWithAnotherRegistryHashGetsTheTableKeptUnderThatHash() throws {
        let other = "uEiAother-registry-hash"
        let extra = Registry.standard.addingClass(ClassSpec(id: "later-hw", status: "active", userVerification: nil))
        let table = try #require(Registry.resolve(for: Self.olderBlock(registryHash: other), liveRegistryHash: Self.liveRegistryHash, tables: [other: extra]))
        #expect(!Self.problems(table, Self.doc).isEmpty)
    }

    /// No table kept for a registry that is not the live one: nothing is returned, and `Registry.table(for:)` stops
    /// the process on that answer instead of reading another edition's rules.
    @Test func aFrozenBlockWithAnUnknownRegistryHashIsFatalNotSilentlyStandard() {
        let block = Self.olderBlock(registryHash: "uEiAunknown-registry-hash")
        #expect(Registry.resolve(for: block, liveRegistryHash: Self.liveRegistryHash, tables: [:]) == nil)
        #expect(Registry.resolve(for: block) == nil)
    }

    /// The tables kept are keyed by the registry file hash of the block they describe; a key that no block carries
    /// is a table for nothing.
    @Test func everyFrozenTableKeyIsTheRegistryHashOfSomeBlock() {
        let hashes = Set(Profiles.versions.compactMap { $0.coreManifest["spec/registry.json"] })
        for key in Registry.frozen.keys { #expect(hashes.contains(key), "\(key)") }
        // and every frozen block resolves: the shipped set can be built
        for block in Profiles.versions { #expect(Registry.resolve(for: block) != nil, "\(block.label)") }
    }

    /// The comparison itself: a block frozen from the live files agrees, and each kind of drift is seen.
    @Test func theGuardSeesAFrozenEditionThatDrifted() throws {
        let text = String(decoding: try Data(contentsOf: Vector.root.appendingPathComponent("spec/registry.json")), as: UTF8.self)
        let manifest = Profiles.coreManifest
        func block(production: String? = nil, registry: String? = nil) -> FrozenEdition {
            FrozenEdition(label: "edition-1", production: production ?? Profiles.hash("production", manifest),
                          fixture: Profiles.hash("fixture", manifest), coreManifest: manifest, fixtureKids: [], registryJSON: registry ?? text)
        }
        // frozen from the live core: its table is `Registry.standard`
        #expect(Self.problems(of: block()) == [])
        // a registry that differs from the table
        #expect(!Self.problems(of: block(registry: text.replacingOccurrences(of: "\"MAX_DEPTH\"", with: "\"MAX_DEPT\""))).isEmpty)
        // a hash that is not the manifest's
        #expect(Self.problems(of: block(production: Encoding.emptyHash)) == ["edition-1: production hash"])
        // a table that differs, and a frozen edition with no table of its own
        let extra = Registry.standard.addingClass(ClassSpec(id: "later-hw", status: "active", userVerification: nil))
        #expect(!Self.problems(extra, Self.doc).isEmpty)
        #expect(Self.problems(Registry.standard, Self.doc).isEmpty)
    }

    /// The contract with `tools/repin.py`: one pair of marker lines frames the generated blocks inside the array literal of `versions`.
    @Test func theEditionMarkersFrameTheRegionOfTheVersionsArray() throws {
        let url = Vector.root.appendingPathComponent("signer/apple/Sources/HandsalCore/Profiles.swift")
        let lines = String(decoding: try Data(contentsOf: url), as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        let open = try #require(lines.firstIndex { $0.hasPrefix("static let versions: [FrozenEdition] = [") })
        let begin = lines.indices.filter { lines[$0] == "// handsal:editions begin" }
        let end = lines.indices.filter { lines[$0] == "// handsal:editions end" }
        #expect(begin.count == 1 && end.count == 1)
        guard let b = begin.first, let e = end.first else { return }
        #expect(open < b && b < e)
        #expect(lines[(e + 1)...].first { !$0.isEmpty } == "]")
    }
}

@Suite("closed schemas (ACT-07, ACT-09, ACT-10)")
struct SchemaTests {
    @Test func validDeviceAddBodyHasNoDefect() {
        #expect(defects("local:handsal.device.add", .object(deviceAddBody())).isEmpty)
    }

    @Test func extraAndMissingKeysAreBodySchema() {
        var extra = deviceAddBody(); extra["x"] = .null
        #expect(defects("local:handsal.device.add", .object(extra)) == ["body_schema"])
        var missing = deviceAddBody(); missing["link_code_hash"] = nil
        #expect(defects("local:handsal.device.add", .object(missing)) == ["body_schema"])
    }

    @Test func act07FormsAreSchemaWhereverTheySit() {
        var bad = deviceAddBody(); bad["link_code_hash"] = .string("uEi")
        #expect(defects("local:handsal.device.add", .object(bad)) == ["schema"])
        var person = deviceAddBody(); person["person"] = .string("Alice")
        #expect(defects("local:handsal.device.add", .object(person)) == ["schema"])
    }

    @Test func otherFormDefectsTakeTheContainerCode() {
        var label = deviceAddBody(); label["label"] = .string("a\"b")
        #expect(defects("local:handsal.device.add", .object(label)) == ["body_schema"])
        var cls = deviceAddBody(); cls["class"] = .string("Apple")
        #expect(defects("local:handsal.device.add", .object(cls)) == ["body_schema"])
    }

    @Test func schemaIsOrderedFirstAmongDefects() throws {
        var both = deviceAddBody(); both["label"] = .string("a\"b"); both["link_code_hash"] = .string("x")
        let found = defects("local:handsal.device.add", .object(both))
        #expect(Set(found) == ["schema", "body_schema"])
        #expect(throws: Refusal("schema")) { try Schema.refuse(found) }
        #expect(throws: Refusal("body_schema")) { try Schema.refuse(["body_schema"]) }
        #expect(throws: Never.self) { try Schema.refuse([]) }
    }

    @Test func resolveListsAreBoundedSortedAndDistinct() {
        func resolve(candidates: [String], heads: [String], overrides: [JValue]) -> JValue {
            .object(["candidates": .array(candidates.map { .string($0) }), "choose": .string(candidates[0]),
                     "heads": .array(heads.map { .string($0) }), "overrides": .array(overrides)])
        }
        let ids = ["a", "b", "c"].map(hs).sorted()
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [ids[0]], overrides: [])).isEmpty)
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: [ids[0]], heads: [ids[0]], overrides: [])) == ["body_schema"])
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: [ids[1], ids[0]], heads: [ids[0]], overrides: [])) == ["body_schema"])
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: [ids[0], ids[0]], heads: [ids[0]], overrides: [])) == ["body_schema"])
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [], overrides: [])) == ["body_schema"])
        let entry: (String, [String]) -> JValue = { r, e in .object(["endorsements": .array(e.map { .string($0) }), "resolve": .string(r)]) }
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [ids[0]], overrides: [entry(ids[0], [ids[1]])])).isEmpty)
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [ids[0]], overrides: [entry(ids[0], [])])) == ["body_schema"])
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [ids[0]], overrides: [entry(ids[1], [ids[0]]), entry(ids[0], [ids[0]])])) == ["body_schema"])
        #expect(defects("local:handsal.chain.resolve", resolve(candidates: Array(ids.prefix(2)), heads: [ids[0]], overrides: [entry(ids[0], [ids[0]]), entry(ids[0], [ids[1]])])) == ["body_schema"])
    }

    @Test func wrongContainerKindIsTheContainerCode() {
        #expect(defects("local:handsal.device.remove", .string("x")) == ["body_schema"])
        #expect(defects("local:handsal.act.endorse", .object(["act": .array([])])) == ["schema"])
    }
}
