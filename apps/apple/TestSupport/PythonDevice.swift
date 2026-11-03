import Foundation
import XCTest

/// One device of the Python demo and the user page, through the `/py/`
/// requests of apps/apple/tools/approver.py. TasksTests and TasksUITests
/// share this file.
struct PythonDevice: Sendable {
    let base: String

    @discardableResult
    func call(_ method: String, _ path: String, _ query: [String: String] = [:]) async throws -> String {
        var c = URLComponents(string: base + "/py/" + path)!
        if !query.isEmpty { c.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) } }
        var r = URLRequest(url: c.url!)
        r.httpMethod = method
        r.timeoutInterval = 90
        let (data, resp) = try await URLSession.shared.data(for: r)
        let text = String(decoding: data, as: UTF8.self)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw PythonError(text: "\(method) \(path): \(code) \(text)") }
        return text
    }

    /// The device ID of the Python device, or of the other device.
    func deviceID(this: Bool) async throws -> String {
        let data = Data(try await call("GET", "devices").utf8)
        let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[Any]])
        return try XCTUnwrap(rows.first { ($0[2] as? Bool) == this }?[0] as? String)
    }
}

struct PythonError: Error, CustomStringConvertible {
    let text: String

    var description: String { text }
}
