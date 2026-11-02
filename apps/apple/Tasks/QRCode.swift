import AVFoundation
import CoreML
import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import Vision

/// QR codes for the enrollment payload (PROTOCOL.md 11.1). The code holds
/// only the session ID and the relay URL, no secret (T6).
enum QRCode {
    /// A QR image of `text`, with each module `scale` pixels wide.
    static func image(_ text: String, scale: CGFloat = 8) -> CGImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: scale, y: scale)) else { return nil }
        return CIContext().createCGImage(out, from: out.extent)
    }

    /// The text of each QR code in `image`, with Vision.
    static func decode(_ image: CGImage) throws -> [String] {
        try decode(VNImageRequestHandler(cgImage: image))
    }

    static func decode(_ handler: VNImageRequestHandler) throws -> [String] {
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr]
        #if targetEnvironment(simulator)
            // On the simulator, revisions 3 and 4 find no code, and the
            // GPU path fails with "Could not create inference context".
            // Revision 2 on the CPU works. A device and macOS use the
            // default revision, and the macOS tests cover it.
            req.revision = VNDetectBarcodesRequestRevision2
            for (stage, devices) in try req.supportedComputeStageDevices {
                if let cpu = devices.first(where: { if case .cpu = $0 { return true } else { return false } }) {
                    req.setComputeDevice(cpu, for: stage)
                }
            }
        #endif
        try handler.perform([req])
        return (req.results ?? []).compactMap(\.payloadStringValue)
    }
}

/// Shows a QR code.
struct QRView: View {
    let text: String

    var body: some View {
        if let img = QRCode.image(text) {
            Image(decorative: img, scale: 1)
                .interpolation(.none)
                .resizable()
                .aspectRatio(1, contentMode: .fit)
                .frame(maxWidth: 280)
                .accessibilityLabel("Enrollment QR code")
        } else {
            Text("No QR code")
        }
    }
}

/// The camera: each frame goes to the Vision request until a frame holds a
/// QR code. The same code runs on iOS and macOS.
final class QRScanner: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "qr-scanner")
    private var found: ((String) -> Void)?
    private var done = false

    func start(found: @escaping (String) -> Void) throws {
        self.found = found
        guard let device = AVCaptureDevice.default(for: .video) else {
            throw SetupError.message("this device has no camera: type the code")
        }
        let input = try AVCaptureDeviceInput(device: device)
        let output = AVCaptureVideoDataOutput()
        output.setSampleBufferDelegate(self, queue: queue)
        session.beginConfiguration()
        guard session.canAddInput(input), session.canAddOutput(output) else {
            session.commitConfiguration()
            throw SetupError.message("the camera is not available")
        }
        session.addInput(input)
        session.addOutput(output)
        session.commitConfiguration()
        queue.async { self.session.startRunning() }
    }

    func stop() {
        queue.async { self.session.stopRunning() }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput buffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !done, let pixels = CMSampleBufferGetImageBuffer(buffer) else { return }
        guard let text = try? QRCode.decode(VNImageRequestHandler(cvPixelBuffer: pixels)).first else { return }
        done = true
        stop()
        DispatchQueue.main.async { self.found?(text) }
    }
}

#if os(iOS)
    struct CameraPreview: UIViewRepresentable {
        let session: AVCaptureSession

        func makeUIView(context: Context) -> PreviewView {
            let v = PreviewView()
            v.layer.session = session
            v.layer.videoGravity = .resizeAspectFill
            return v
        }

        func updateUIView(_ uiView: PreviewView, context: Context) {}

        final class PreviewView: UIView {
            override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
            override var layer: AVCaptureVideoPreviewLayer { super.layer as! AVCaptureVideoPreviewLayer }
        }
    }
#else
    struct CameraPreview: NSViewRepresentable {
        let session: AVCaptureSession

        func makeNSView(context: Context) -> NSView {
            let v = NSView()
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            v.layer = layer
            v.wantsLayer = true
            return v
        }

        func updateNSView(_ nsView: NSView, context: Context) {}
    }
#endif

/// Scans a QR code with the camera, or takes a typed code.
struct ScanView: View {
    let found: (String) -> Void
    @State private var scanner = QRScanner()
    @State private var typed = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            CameraPreview(session: scanner.session)
                .frame(minHeight: 240)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            if let error { Text(error).foregroundStyle(.secondary) }
            HStack {
                TextField("Or type the code", text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Button("Use code") { found(typed) }
                    .disabled(typed.isEmpty)
            }
        }
        .onAppear {
            do { try scanner.start(found: found) } catch { self.error = "\(error)" }
        }
        .onDisappear { scanner.stop() }
    }
}
