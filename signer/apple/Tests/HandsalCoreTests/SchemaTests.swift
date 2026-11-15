import Foundation
import HandsalCore
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
/// second copy, so this test compares them with the file and fails when they drift.
@Suite("registry tables match spec/registry.json")
struct RegistryGuardTests {
    static let doc: [String: JValue] = {
        let url = Vector.root.appendingPathComponent("spec/registry.json")
        guard case .object(let doc) = try! TestJSON.parse([UInt8](try! Data(contentsOf: url))) else { fatalError() }
        return doc
    }()

    @Test func methodTable() throws {
        guard case .array(let entries)? = Self.doc["methods"] else { Issue.record("no methods"); return }
        #expect(Registry.standard.methods.count == entries.count)
        for entry in entries {
            guard case .object(let m) = entry, case .string(let name)? = m["method"] else { continue }
            guard let spec = Registry.standard.methods[name] else { Issue.record("missing \(name)"); continue }
            #expect(m["head"] == .string(spec.head.rawValue), "\(name) head")
            #expect(m["inputs_hash"] == .string(spec.inputsHash), "\(name) inputs_hash")
            #expect(m["outputs_hash"] == .string(spec.outputsHash), "\(name) outputs_hash")
            #expect(m["act_extra_keys"] == .array(spec.actExtraKeys.map { .string($0) }), "\(name) extra keys")
            #expect(m["body"] == spec.body.registryJSON, "\(name) body")
        }
    }

    @Test func classTable() throws {
        guard case .array(let entries)? = Self.doc["key_classes"], case .array(let fixture)? = Self.doc["fixture_only"] else {
            Issue.record("no classes"); return
        }
        func check(_ list: [JValue], _ table: [String: ClassSpec]) {
            #expect(table.count == list.count)
            for entry in list {
                guard case .object(let c) = entry, case .string(let id)? = c["id"], let spec = table[id] else {
                    Issue.record("class missing"); continue
                }
                #expect(c["status"] == .string(spec.status), "\(id) status")
                let uv: JValue = spec.userVerification.map { .string($0) } ?? .null
                #expect(c["user_verification"] == uv, "\(id) user_verification")
            }
        }
        check(entries, Registry.standard.classes)
        check(fixture, Registry.standard.fixtureOnly)
    }

    @Test func constantsAndExtraKeyTypes() throws {
        guard case .object(let constants)? = Self.doc["constants"] else { Issue.record("no constants"); return }
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
        #expect(!flat.isEmpty)
        for (path, n) in flat {
            // `NAME.value` is the registry's way of writing a plain constant `NAME`.
            let name = path.hasSuffix(".value") ? String(path.dropLast(6)) : path
            let key = name.hasPrefix(".") ? String(name.dropFirst()) : name
            #expect(Registry.standard.number(key) == n, "\(key)")
        }
        guard case .object(let types)? = Self.doc["act_extra_key_types"] else { return }
        #expect(Registry.standard.actExtraKeyTypes.count == types.count)
        for (key, value) in types { #expect(value == .string(Registry.standard.actExtraKeyTypes[key]?.rawValue ?? "?"), "\(key)") }
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
