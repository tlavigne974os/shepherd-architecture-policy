import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import arch_check  # noqa: E402
from swift_lex import tokens  # noqa: E402

POLICY = HERE / "policy" / "ipad-app.policy.json"

PROJECT_OK = """name: BaxterToo
targets:
  BaxterToo:
    type: application
    dependencies:
      - package: BaxterMiddlewareKernel
        product: BaxterMiddlewareKernel
      - package: BaxterVoiceEngine
        product: BaxterVoiceEngine
      - package: ChessKit
        product: ChessKit
  FrameTests:
    type: bundle.unit-test
    dependencies:
      - package: CocoaMQTT
        product: CocoaMQTT
"""


def scratch(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="arch-check-"))
    files = {"project.yml": PROJECT_OK, **files}
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def run(files: dict[str, str], changed=None):
    return arch_check.run(scratch(files), POLICY, changed)


def rules(violations):
    return sorted({v["rule"] for v in violations})


class LexerTests(unittest.TestCase):
    def texts(self, src):
        return [t.text for t in tokens(src)]

    def test_comments_and_strings_are_not_code(self):
        src = '// UserDefaults\n/* URLSession /* nested */ AVAudioEngine */\nlet s = "FileManager"\nlet r = #"URLSession"#\n'
        self.assertEqual(self.texts(src), ["let", "s", "=", "let", "r", "="])

    def test_interpolation_is_code(self):
        self.assertIn("UserDefaults", self.texts('let s = "value \\(UserDefaults.standard.string(forKey: "k") ?? "")"'))

    def test_multiline_string_and_line_numbers(self):
        toks = list(tokens('let a = """\nURLSession\n"""\nlet b = FileManager.default\n'))
        self.assertEqual([(t.text, t.line) for t in toks if t.text == "FileManager"], [("FileManager", 4)])

    def test_nested_string_inside_interpolation(self):
        self.assertIn("Logger", self.texts('let s = "a \\(f("b \\(Logger.self)"))"'))


class OrdinaryCodePasses(unittest.TestCase):
    def test_rendering_and_computation(self):
        view = """import SwiftUI
import AVFoundation
struct Card: View {
    @State private var tick = 0
    var body: some View {
        VStack { Text("UserDefaults is only a word here"); Image(systemName: "waveform") }
            .onAppear { tick += 1 }
    }
}
func mix(_ a: AVAudioPCMBuffer, _ f: AVAudioFormat) -> Double { Double(a.frameLength) * f.sampleRate }
func request(_ url: URL) -> URLRequest { var r = URLRequest(url: url); r.httpMethod = "GET"; return r }
enum Origin { case system, user }
final class Gate { func open(stream: Int) {} ; func write(_ x: Int) {} ; func connect() {} }
let d = JSONDecoder()
"""
        self.assertEqual(run({"Frame/UI/Card.swift": view}), [])

    def test_member_calls_named_like_syscalls_pass(self):
        src = "final class X { func go(g: Gate, o: Origin) { g.open(stream: 1); g.write(2); if o == .system {} } }\n"
        self.assertEqual(run({"Frame/Voice/X.swift": src}), [])


class ProhibitedExamplesAreRejected(unittest.TestCase):
    CASES = {
        "hardware-audio": ["let e = AVAudioEngine()", "let s = AVAudioSession.sharedInstance()", "typealias E = AVAudioEngine",
                           "let e = AVFoundation.AVAudioEngine()", "let r = SFSpeechRecognizer()"],
        "hardware-camera-sensors": ["let c = AVCaptureSession()"],
        "hardware-media-playback": ["let p = AVPlayer()", "let a = AVURLAsset(url: u)"],
        "hardware-display": ["UIApplication.shared.isIdleTimerDisabled = true", "let b = UIScreen.main"],
        "network": ["let s = URLSession.shared", "let w = WKWebView()", "let c = Foundation.URLSession(configuration: .default)",
                    "let d = try Data(contentsOf: url)", "let t = String(contentsOf: url)", "let m = CocoaMQTT(clientID: id)",
                    "let l = NWListener(using: .tcp)", "AsyncImage(url: u)"],
        "persistence": ["let d = UserDefaults.standard", "let f = FileManager.default", "try data.write(to: url)",
                        "let h = FileHandle(forWritingAtPath: p)", "SecItemAdd(q, nil)", "let fd = open(path, 0)"],
        "logging": ["let l = Logger(subsystem: \"a\", category: \"b\")", "NSLog(\"x\")", "print(\"x\")", "os_log(\"x\")"],
        "escape-routes": ["let p = Process()", "let h = dlopen(path, 0)", "let c: AnyClass? = NSClassFromString(n)",
                          "@_silgen_name(\"foo\") func foo()", "system(\"ls\")"],
    }

    def test_each_example_is_rejected_under_its_rule(self):
        for rule, examples in self.CASES.items():
            for example in examples:
                with self.subTest(example=example):
                    found = run({"Frame/Feature/Bypass.swift": f"import Foundation\nfunc f() {{\n    {example}\n}}\n"})
                    self.assertIn(rule, rules(found), f"{example!r} -> {found}")

    def test_interpolated_bypass_is_rejected(self):
        found = run({"Frame/Feature/Hidden.swift": 'let s = "x \\(UserDefaults.standard.string(forKey: "k") ?? "")"\n'})
        self.assertEqual(rules(found), ["persistence"])

    def test_violations_carry_file_line_and_the_supported_route(self):
        found = run({"Frame/Feature/Bypass.swift": "\n\nlet s = URLSession.shared\n"})
        self.assertEqual((found[0]["file"], found[0]["line"]), ("Frame/Feature/Bypass.swift", 3))
        self.assertIn("kernel", found[0]["message"].lower())


class ZonesAndExemptions(unittest.TestCase):
    def test_kernel_package_may_use_the_apis(self):
        src = "import AVFoundation\nfinal class K { let e = AVAudioEngine(); let d = UserDefaults.standard }\n"
        self.assertEqual(run({"Packages/BaxterMiddlewareKernel/Sources/BaxterMiddlewareKernel/K.swift": src}), [])

    def test_tests_and_tools_are_outside_the_app_zone(self):
        src = "let s = URLSession.shared\n"
        self.assertEqual(run({"FrameTests/T.swift": src, "tools/Helper/H.swift": src}), [])

    def test_linked_package_sources_are_scanned(self):
        found = run({"Packages/BaxterVoiceEngine/Sources/BaxterVoiceEngine/E.swift": "let e = AVAudioEngine()\n"})
        self.assertEqual(rules(found), ["hardware-audio"])

    def test_native_package_sources_are_scanned(self):
        found = run({"Packages/BaxterVoiceEngine/Sources/BaxterCaptureRing/R.m": "// ok\nint fd = open(\"x\", 0);\n"})
        self.assertEqual(rules(found), ["persistence"])

    def test_an_allowed_site_is_per_file_rule_and_match_not_a_count(self):
        policy = json.loads(POLICY.read_text())
        policy["allowed_sites"] = [{"file": "Frame/A.swift", "rule": "network", "match": "URLSession", "reason": "test"}]
        tmp = Path(tempfile.mkdtemp()) / "p.json"
        tmp.write_text(json.dumps(policy))
        root = scratch({"Frame/A.swift": "let a = URLSession.shared\n", "Frame/B.swift": "let b = URLSession.shared\n"})
        found = arch_check.run(root, tmp)
        self.assertEqual([(v["file"]) for v in found], ["Frame/B.swift"])


class DependenciesAndProtectedPaths(unittest.TestCase):
    def test_clean_project_and_unit_test_only_io_library_pass(self):
        self.assertEqual(run({}), [])

    def test_app_linking_an_io_bearing_product_fails(self):
        bad = PROJECT_OK.replace("      - package: ChessKit\n        product: ChessKit\n",
                                 "      - package: ChessKit\n        product: ChessKit\n      - package: CocoaMQTT\n        product: CocoaMQTT\n")
        self.assertEqual(rules(run({"project.yml": bad})), ["dependency-io-bearing"])

    def test_unlisted_product_fails(self):
        bad = PROJECT_OK.replace("product: ChessKit", "product: SomeNewSdk")
        self.assertEqual(rules(run({"project.yml": bad})), ["dependency-unlisted"])

    def test_changing_the_boundary_in_a_feature_change_fails(self):
        found = run({}, changed=["Frame/UI/Card.swift", "tools/architecture-policy/policy/ipad-app.policy.json",
                                 ".github/workflows/architecture-check.yml"])
        self.assertEqual(sorted(v["file"] for v in found),
                         [".github/workflows/architecture-check.yml", "tools/architecture-policy/policy/ipad-app.policy.json"])

    def test_candidate_cannot_bring_its_own_policy(self):
        weak = json.loads(POLICY.read_text())
        weak["rules"] = []
        tmp = Path(tempfile.mkdtemp()) / "weak.json"
        tmp.write_text(json.dumps(weak))
        with self.assertRaises(arch_check.PolicyError):
            arch_check.run(scratch({}), tmp, trusted_policy_path=POLICY)


if __name__ == "__main__":
    unittest.main()
