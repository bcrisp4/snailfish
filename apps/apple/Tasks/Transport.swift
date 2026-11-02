import Foundation
import Snailfish

/// Sends the engine requests. The app owns HTTP, TLS and retries (DESIGN.md
/// "App integration"). The session follows no redirects, because the
/// request signature covers the relay authority.
final class Transport: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 30
        c.httpCookieAcceptPolicy = .never
        c.httpShouldSetCookies = false
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }()

    func send(_ req: Request) async throws -> (UInt16, [Header], Data) {
        guard let url = URL(string: req.url) else { throw URLError(.badURL) }
        var r = URLRequest(url: url)
        r.httpMethod = req.method
        for h in req.headers { r.addValue(h.value, forHTTPHeaderField: h.name) }
        if !req.body.isEmpty { r.httpBody = req.body }
        let (data, resp) = try await session.data(for: r)
        guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        let headers = http.allHeaderFields.compactMap { k, v -> Header? in
            guard let k = k as? String, let v = v as? String else { return nil }
            return Header(name: k.lowercased(), value: v)
        }
        return (UInt16(http.statusCode), headers, data)
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
