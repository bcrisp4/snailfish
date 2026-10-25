// The shared test vectors through the Swift binding (DESIGN.md M1).
// The checks match crates/engine/tests/vectors.rs and the Python tests, so a
// marshalling fault in the Swift binding fails here.

import Foundation
import XCTest

@testable import Snailfish

private func loadVector(_ name: String) throws -> Any {
    let base = try XCTUnwrap(Bundle.module.url(forResource: "vectors", withExtension: nil))
    return try JSONSerialization.jsonObject(with: Data(contentsOf: base.appendingPathComponent(name)))
}

private func hex(_ s: Any?) throws -> Data {
    let text = try XCTUnwrap(s as? String)
    var out = Data(capacity: text.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        out.append(try XCTUnwrap(UInt8(text[index..<next], radix: 16)))
        index = next
    }
    return out
}

private func toHex(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

private func str(_ v: Any?) throws -> String {
    try XCTUnwrap(v as? String)
}

private func dict(_ v: Any?) throws -> [String: Any] {
    try XCTUnwrap(v as? [String: Any])
}

private func list(_ v: Any?) throws -> [[String: Any]] {
    try XCTUnwrap(v as? [[String: Any]])
}

final class VectorTests: XCTestCase {
    private var protocolVectors: [String: Any] = [:]
    private var signKeys: [String: Data] = [:]
    private var sealSeeds: [String: Data] = [:]

    override func setUpWithError() throws {
        protocolVectors = try dict(loadVector("protocol.json"))
        for d in try list(protocolVectors["devices"]) {
            let pk = try signPublicKey(seed: hex(d["sign_seed"]))
            let spk = try sealPublicKey(seed: hex(d["seal_seed"]))
            XCTAssertEqual(try deviceId(signPk: pk, sealPk: spk), try str(d["id"]))
            signKeys[try str(d["name"])] = pk
            sealSeeds[try str(d["id"])] = try hex(d["seal_seed"])
        }
        for r in try list(protocolVectors["recovery"]) {
            let secret = try recoveryParse(text: str(r["display"]))
            XCTAssertEqual(try recoveryDisplay(secret: secret), try str(r["display"]))
            let seeds = try recoveryDerive(secret: secret)
            let pk = try signPublicKey(seed: seeds[0])
            XCTAssertEqual(try recoveryId(signPk: pk, sealPk: sealPublicKey(seed: seeds[1])), try str(r["id"]))
            signKeys[try str(r["name"])] = pk
            sealSeeds[try str(r["id"])] = seeds[1]
        }
    }

    func testFrames() throws {
        for f in try list(protocolVectors["frames"]) {
            let parts = try XCTUnwrap(f["parts"] as? [String]).map { try hex($0) }
            XCTAssertEqual(frame(parts: parts), try hex(f["frame"]))
        }
    }

    func testLogChainSignaturesKeySetsAndCiphertexts() throws {
        let log = try dict(protocolVectors["log"])
        let logId = try str(log["log_id"])
        let appKeys = try XCTUnwrap(log["app_keys"] as? [String: String])
        let commitments = try XCTUnwrap(log["commitments"] as? [String: String])
        var plaintexts: [Int: String] = [:]
        for c in try list(protocolVectors["ciphertexts"]) {
            plaintexts[try XCTUnwrap(c["entry"] as? Int)] = try str(c["plaintext"])
        }
        var digest = try digest0(logId: logId)
        XCTAssertEqual(toHex(digest), try str(log["digest0"]))
        var opened = 0
        for e in try list(log["entries"]) {
            let position = try XCTUnwrap(e["position"] as? Int)
            let env = try parseEnvelope(text: Data(str(e["envelope"]).utf8))
            let signer = try XCTUnwrap(signKeys[try str(e["signer"])])
            XCTAssertTrue(verifyRecord(publicKey: signer, payloadType: env.payloadType, payload: env.payload, signature: env.sig))
            let info = try checkPayload(payloadType: env.payloadType, payload: env.payload)
            XCTAssertEqual(info.log, logId)
            XCTAssertEqual(try envelopeToJson(envelope: env, keyid: info.author), try str(e["envelope"]))
            let rh = try recordHash(payloadType: env.payloadType, payload: env.payload, sig: env.sig)
            XCTAssertEqual(toHex(rh), try str(e["record_hash"]))
            XCTAssertEqual(toHex(info.changeId ?? Data()), try str(e["change_id"]))
            let eh = try entryHash(payloadType: env.payloadType, changeId: info.changeId, recordHash: rh)
            XCTAssertEqual(toHex(eh), try str(e["entry_hash"]))
            digest = try digestNext(prev: digest, n: UInt64(position), entryHash: eh)
            XCTAssertEqual(toHex(digest), try str(e["digest"]), "entry \(position)")
            for ks in info.keySets {
                let seed = try XCTUnwrap(sealSeeds[ks.to])
                let keys = try openKeySet(sealSeed: seed, logId: logId, to: ks.to, epochs: ks.epochs, sealed: ks.sealed)
                for (epoch, key) in zip(ks.epochs, keys) {
                    XCTAssertEqual(toHex(key), appKeys[String(epoch)])
                    XCTAssertEqual(toHex(try keyCommitment(logId: logId, epoch: epoch, key: key)), commitments[String(epoch)])
                }
                opened += 1
            }
            if let expected = plaintexts[position] {
                let epoch = (try str(e["name"])) == "change-epoch-2" ? "2" : "1"
                let key = try hex(appKeys[epoch])
                XCTAssertEqual(toHex(try decryptPayload(appKey: key, payloadType: env.payloadType, payload: env.payload)), expected)
            }
        }
        XCTAssertEqual(opened, try list(protocolVectors["key_sets"]).count)
    }

    func testEnvelopeVariants() throws {
        for e in try list(protocolVectors["envelopes"]) {
            let text = Data(try str(e["envelope"]).utf8)
            if try XCTUnwrap(e["valid"] as? Bool) {
                let env = try parseEnvelope(text: text)
                let rh = try recordHash(payloadType: env.payloadType, payload: env.payload, sig: env.sig)
                XCTAssertEqual(toHex(rh), try str(e["record_hash"]))
            } else {
                let name = try str(e["name"])
                XCTAssertThrowsError(try parseEnvelope(text: text), name)
            }
        }
    }

    func testStrictJson() throws {
        let cases = try list(dict(loadVector("strict-json.json"))["cases"])
        XCTAssertGreaterThanOrEqual(cases.count, 50)
        for c in cases {
            let bytes = try (c["payload"] as? String).map { Data($0.utf8) } ?? hex(c["payload_hex"])
            let name = try str(c["name"])
            let ptype = try str(c["payload_type"])
            if try XCTUnwrap(c["valid"] as? Bool) {
                XCTAssertNoThrow(try checkPayload(payloadType: ptype, payload: bytes), name)
            } else {
                XCTAssertThrowsError(try checkPayload(payloadType: ptype, payload: bytes), name) { error in
                    guard case SnailfishError.Invalid = error else {
                        return XCTFail("\(name): \(error)")
                    }
                }
            }
        }
    }

    func testRecoveryKeys() throws {
        let v = try dict(loadVector("recovery-key.json"))
        for c in try list(v["valid"]) {
            XCTAssertEqual(toHex(try recoveryParse(text: str(c["text"]))), try str(c["secret"]))
        }
        for c in try list(v["invalid"]) {
            let name = try str(c["name"])
            XCTAssertThrowsError(try recoveryParse(text: str(c["text"])), name)
        }
    }

    func testCctvEd25519() throws {
        let vectors = try XCTUnwrap(loadVector("third_party/cctv-ed25519.json") as? [[String: Any]])
        XCTAssertEqual(vectors.count, 914)
        let allowed: Set<String> = ["low_order_component_A", "low_order_component_R"]
        for t in vectors {
            let flags = Set((t["flags"] as? [String]) ?? [])
            let got = ed25519Verify(publicKey: try hex(t["key"]), msg: Data(try str(t["msg"]).utf8), signature: try hex(t["sig"]))
            XCTAssertEqual(got, flags.isSubset(of: allowed), "vector \(t["number"] ?? "?")")
        }
    }

    func testEngineSkeleton() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = try Engine.open(dataDir: dir.path, relayUrl: "https://r.example/", appId: "com.example.tasks")
        XCTAssertThrowsError(try Engine.open(dataDir: dir.path, relayUrl: "https://r.example", appId: "a")) { error in
            XCTAssertEqual(error as? SnailfishError, .Locked)
        }
        XCTAssertEqual(try engine.newChangeId().count, 16)
        let sync = try engine.startSync()
        let req = try XCTUnwrap(try sync.nextRequest())
        XCTAssertEqual(req.url, "https://r.example/v1/info")
        try sync.handleResponse(status: 200, headers: [], body: Data(#"{"levels":[0]}"#.utf8))
        XCTAssertEqual(try engine.status(), .relayTooOld)
        let again = try engine.startSync()
        _ = try again.nextRequest()
        try again.handleResponse(status: 503, headers: [Header(name: "retry-after", value: "5")], body: Data())
        XCTAssertEqual(try engine.status(), .relayUnavailable)
        XCTAssertThrowsError(try deviceId(signPk: Data(count: 32), sealPk: Data(count: 1215)))
    }
}
