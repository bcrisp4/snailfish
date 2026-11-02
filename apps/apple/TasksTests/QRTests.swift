import Snailfish
import XCTest

@testable import Tasks

final class QRTests: XCTestCase {
    /// [ENR-1], PROTOCOL.md 11.1: the QR image of an enrollment payload
    /// reads back through the Vision request of the camera scanner, and the
    /// engine accepts the text. The simulator has no camera, so the test
    /// feeds the generated image to Vision.
    func testEnrollmentPayloadRoundTripsThroughVision() throws {
        let n = try NewEnrollment(relayUrl: "https://sync.example.net", keys: try newDeviceKeys(), name: "B", scanned: nil)
        let payload = try XCTUnwrap(try n.payload())
        let image = try XCTUnwrap(QRCode.image(payload))
        let read = try QRCode.decode(image)
        XCTAssertEqual(read, [payload])
        XCTAssertEqual(try enrollParsePayload(text: read[0]).role, "n")
    }
}
