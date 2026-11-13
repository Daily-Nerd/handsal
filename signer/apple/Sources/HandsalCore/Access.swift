/// Read access to a parsed value. A shape that is not there answers nil, so a caller that has
/// already validated a value reads it without a force unwrap.
extension JValue {
    public var str: String? { if case .string(let s) = self { return s } else { return nil } }
    public var dict: [String: JValue]? { if case .object(let o) = self { return o } else { return nil } }
    public var list: [JValue]? { if case .array(let a) = self { return a } else { return nil } }

    public subscript(key: String) -> JValue? { dict?[key] }
}
