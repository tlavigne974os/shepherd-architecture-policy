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


def make_pbx(targets: dict, local_packages=("Packages/BaxterMiddlewareKernel", "Packages/BaxterVoiceEngine")) -> str:
    """A minimal committed project file: `targets` maps a target name to {"products": [...], "scripts": [...]}."""
    objects, n = [], 0

    def oid() -> str:
        nonlocal n
        n += 1
        return f"{n:024X}"

    for name, spec in targets.items():
        product_ids = []
        for product in spec.get("products", []):
            pid = oid()
            product_ids.append(pid)
            objects.append(f"{pid} = {{isa = XCSwiftPackageProductDependency; productName = {product};}};")
        phase_ids = []
        for script in spec.get("scripts", []):
            sid = oid()
            phase_ids.append(sid)
            escaped = script.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            objects.append(f'{sid} = {{isa = PBXShellScriptBuildPhase; shellScript = "{escaped}";}};')
        source_files = []
        for path in spec.get("sources", []):
            fid, bid = oid(), oid()
            objects.append(f"{fid} = {{isa = PBXFileReference; path = \"{path}\"; sourceTree = SOURCE_ROOT;}};")
            objects.append(f"{bid} = {{isa = PBXBuildFile; fileRef = {fid};}};")
            source_files.append(bid)
        if source_files:
            sid = oid()
            phase_ids.append(sid)
            objects.append(f"{sid} = {{isa = PBXSourcesBuildPhase; files = ({', '.join(source_files)});}};")
        objects.append(f"{oid()} = {{isa = PBXNativeTarget; name = {name}; "
                       f"packageProductDependencies = ({', '.join(product_ids)}); buildPhases = ({', '.join(phase_ids)});}};")
    for path in local_packages:
        objects.append(f"{oid()} = {{isa = XCLocalSwiftPackageReference; relativePath = {path};}};")
    return "// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tobjects = {\n\t\t" + "\n\t\t".join(objects) + "\n\t};\n\trootObject = 0;\n}\n"


APP_PRODUCTS = ["BaxterMiddlewareKernel", "BaxterVoiceEngine", "ChessKit"]
PBX_OK = make_pbx({"BaxterToo": {"products": APP_PRODUCTS}, "BaxterTooRestricted": {"products": APP_PRODUCTS},
                   "CaptureWitnessObservation": {"products": APP_PRODUCTS}})
VOICE_MANIFEST = '// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "BaxterVoiceEngine", ' \
                 'dependencies: [.package(path: "../BaxterMiddlewareKernel")], targets: [.target(name: "BaxterVoiceEngine")])\n'


def scratch(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="arch-check-"))
    files = {"project.yml": PROJECT_OK, "BaxterToo.xcodeproj/project.pbxproj": PBX_OK,
             "Packages/BaxterVoiceEngine/Package.swift": VOICE_MANIFEST, **files}
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def run(files: dict[str, str], changed=None, policy=None):
    return arch_check.run(scratch(files), policy or POLICY, changed)


def policy_with(mutate) -> Path:
    policy = json.loads(POLICY.read_text())
    mutate(policy)
    tmp = Path(tempfile.mkdtemp()) / "p.json"
    tmp.write_text(json.dumps(policy))
    return tmp


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

    def test_the_kernel_package_is_owner_protected_even_though_it_is_exempt_from_the_rules(self):
        # kernel_zones exempts the kernel from the I/O rules (it IS the I/O owner); protected_paths is what makes
        # any change to it need the owner, independent of CODEOWNERS.
        found = run({}, changed=["Frame/UI/Card.swift", "Packages/BaxterMiddlewareKernel/Sources/BaxterMiddlewareKernel/Mode/CaptureGovernor.swift",
                                 "Packages/BaxterMiddlewareKernel/Package.swift"])
        self.assertEqual(sorted(v["file"] for v in found),
                         ["Packages/BaxterMiddlewareKernel/Package.swift",
                          "Packages/BaxterMiddlewareKernel/Sources/BaxterMiddlewareKernel/Mode/CaptureGovernor.swift"])
        self.assertEqual({v["rule"] for v in found}, {"protected-path"})
        self.assertEqual(run({}, changed=["Frame/UI/Card.swift", "Packages/BaxterVoiceEngine/Package.swift"]), [])

    def test_the_removed_sdk29_product_is_no_longer_listed(self):
        self.assertNotIn("BaxterVoiceEngineSDK29", json.loads(POLICY.read_text())["dependencies"]["kernel_only_products"])

    def test_candidate_cannot_bring_its_own_policy(self):
        weak = json.loads(POLICY.read_text())
        weak["rules"] = []
        tmp = Path(tempfile.mkdtemp()) / "weak.json"
        tmp.write_text(json.dumps(weak))
        with self.assertRaises(arch_check.PolicyError):
            arch_check.run(scratch({}), tmp, trusted_policy_path=POLICY)


class ShippedCodeCoverage(unittest.TestCase):
    """P3: every native suffix, the whole allowed package set, the test seams and the committed project file."""

    def test_every_native_suffix_in_the_app_zone_is_scanned(self):
        for suffix in (".m", ".mm", ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".s"):
            with self.subTest(suffix=suffix):
                found = run({f"Frame/Native/Bypass{suffix}": "int f(void) { return open(\"x\", 0); }\n"})
                self.assertIn("persistence", rules(found), suffix)

    def test_ordinary_native_source_in_the_app_zone_passes(self):
        self.assertEqual(run({"Frame/Native/Math.c": "int add(int a, int b) { return a + b; }\n"}), [])

    def test_prebuilt_native_code_in_a_shipped_zone_is_refused_unless_named(self):
        for path in ("Frame/Vendor/libx.a", "Frame/Vendor/x.o", "Frame/Vendor/x.dylib", "Frame/Vendor/X.xcframework/Info.plist",
                     "Packages/BaxterVoiceEngine/Sources/X/Y.framework/Y"):
            with self.subTest(path=path):
                self.assertEqual(rules(run({path: "binary"})), ["native-artifact"], path)
        named = "Packages/TensorFlowLiteC/Frameworks/TensorFlowLiteC.xcframework/Info.plist"
        self.assertEqual(run({named: "plist"}), [], "the two vendored TensorFlow Lite C xcframeworks are named")

    def test_package_tests_are_not_shipped_and_not_scanned(self):
        self.assertEqual(run({"Packages/BaxterVoiceEngine/Tests/T.swift": "let d = try Data(contentsOf: u)\n"}), [])

    def test_the_whole_voice_engine_package_is_scanned_not_just_four_directories(self):
        found = run({"Packages/BaxterVoiceEngine/Sources/BaxterMicrofrontend/M.m": "int fd = open(\"x\", 0);\n"})
        self.assertEqual(rules(found), ["persistence"])

    def test_a_local_package_the_project_links_but_no_zone_covers_is_a_bypass(self):
        pbx = make_pbx({"BaxterToo": {"products": APP_PRODUCTS}, "BaxterTooRestricted": {"products": APP_PRODUCTS},
                        "CaptureWitnessObservation": {"products": APP_PRODUCTS}},
                       local_packages=("Packages/BaxterMiddlewareKernel", "Packages/BaxterVoiceEngine", "Packages/Rogue"))
        found = run({"BaxterToo.xcodeproj/project.pbxproj": pbx, "Packages/Rogue/Package.swift": "// rogue\n",
                     "Packages/Rogue/Sources/R.swift": "let s = URLSession.shared\n"})
        self.assertEqual(rules(found), ["package-unzoned"])
        self.assertEqual([v["file"] for v in found], ["Packages/Rogue"])

    def test_manifest_spacing_variants_do_not_hide_an_unzoned_path_dependency(self):
        for spelled in ('.package(path : "../Sneaky")', '.package (name : "S", path : "../Sneaky")',
                        '.package(\n    path:\n    "../Sneaky")'):
            with self.subTest(spelled=spelled):
                manifest = VOICE_MANIFEST.replace('.package(path: "../BaxterMiddlewareKernel")',
                                                  '.package(path: "../BaxterMiddlewareKernel"), ' + spelled)
                found = run({"Packages/BaxterVoiceEngine/Package.swift": manifest})
                self.assertEqual(rules(found), ["package-unzoned"], spelled)

    def test_a_path_dependency_of_a_zoned_package_must_be_zoned_too(self):
        manifest = VOICE_MANIFEST.replace('.package(path: "../BaxterMiddlewareKernel")',
                                          '.package(path: "../BaxterMiddlewareKernel"), .package(path: "../Sneaky")')
        found = run({"Packages/BaxterVoiceEngine/Package.swift": manifest})
        self.assertEqual(rules(found), ["package-unzoned"])
        self.assertEqual([v["file"] for v in found], ["Packages/Sneaky"])
        inside = VOICE_MANIFEST.replace('.package(path: "../BaxterMiddlewareKernel")',
                                        '.package(path: "../BaxterMiddlewareKernel"), .package(path: "Dependencies/Inner")')
        self.assertEqual(run({"Packages/BaxterVoiceEngine/Package.swift": inside,
                              "Packages/BaxterVoiceEngine/Dependencies/Inner/Package.swift": "// inner\n"}), [])

    def test_package_manifests_cannot_add_unscanned_code_or_flags(self):
        for fragment in ('unsafeFlags(["-O0"])', '.binaryTarget(name: "B", path: "B.xcframework")', '.systemLibrary(name: "S")',
                         '.plugin(name: "P", package: "Q")', '.package(url: "https://example.com/x.git", from: "1.0.0")'):
            with self.subTest(fragment=fragment):
                manifest = VOICE_MANIFEST.replace("targets: [", f"extra: [{fragment}], targets: [")
                self.assertIn("package-build-input", rules(run({"Packages/BaxterVoiceEngine/Package.swift": manifest})), fragment)

    def test_the_debug_test_seams_are_rejected_in_shipped_code_but_not_in_the_kernel_or_tests(self):
        for symbol in ("debugStubbed", "debugProtocolClasses", "unscopedWriterForTests"):
            with self.subTest(symbol=symbol):
                src = f"let x = Seam.{symbol}\n"
                self.assertEqual(rules(run({"Frame/Feature/S.swift": src})), ["test-seam"])
                self.assertEqual(rules(run({"Packages/BaxterVoiceEngine/Sources/BaxterVoiceEngine/S.swift": src})), ["test-seam"])
                self.assertEqual(run({"Packages/BaxterMiddlewareKernel/Sources/BaxterMiddlewareKernel/S.swift": src,
                                      "FrameTests/S.swift": src}), [])

    def test_the_committed_project_file_is_checked_for_linked_products(self):
        io = make_pbx({"BaxterToo": {"products": APP_PRODUCTS + ["CocoaMQTT"]}, "BaxterTooRestricted": {"products": APP_PRODUCTS},
                       "CaptureWitnessObservation": {"products": APP_PRODUCTS + ["SneakyKit"]}})
        found = run({"BaxterToo.xcodeproj/project.pbxproj": io})
        self.assertEqual(sorted((v["rule"], v["match"]) for v in found),
                         [("dependency-io-bearing", "BaxterToo:CocoaMQTT"), ("dependency-unlisted", "CaptureWitnessObservation:SneakyKit")])
        self.assertTrue(all(v["file"] == "BaxterToo.xcodeproj/project.pbxproj" for v in found))

    def test_an_unreadable_or_missing_project_file_fails_closed(self):
        self.assertEqual(rules(run({"BaxterToo.xcodeproj/project.pbxproj": "not a project"})), ["project-unreadable"])
        root = scratch({})
        (root / "BaxterToo.xcodeproj/project.pbxproj").unlink()
        self.assertEqual(rules(arch_check.run(root, POLICY)), ["project-unreadable"])

    def test_app_target_run_scripts_must_be_on_the_allowlist(self):
        script = "set -eu\necho \"build input\"\n"
        pbx = make_pbx({"BaxterToo": {"products": APP_PRODUCTS, "scripts": [script]}, "BaxterTooRestricted": {"products": APP_PRODUCTS},
                        "CaptureWitnessObservation": {"products": APP_PRODUCTS}})
        found = run({"BaxterToo.xcodeproj/project.pbxproj": pbx})
        self.assertEqual(rules(found), ["build-phase-script"])
        digest = arch_check.pbxproj.sha256_of(script)
        allow = policy_with(lambda p: p.setdefault("allowed_build_scripts", []).append({"sha256": digest, "note": "test"}))
        self.assertEqual(run({"BaxterToo.xcodeproj/project.pbxproj": pbx}, policy=allow), [])

    def test_a_source_the_project_compiles_from_outside_every_zone_is_refused(self):
        for rogue in ("scripts/Evil.swift", "tools/Helper/H.m", "../outside/X.swift", "/abs/X.swift"):
            with self.subTest(rogue=rogue):
                pbx = make_pbx({"BaxterToo": {"products": APP_PRODUCTS, "sources": ["Frame/UI/Card.swift", rogue]},
                                "BaxterTooRestricted": {"products": APP_PRODUCTS}, "CaptureWitnessObservation": {"products": APP_PRODUCTS}})
                found = run({"BaxterToo.xcodeproj/project.pbxproj": pbx})
                self.assertEqual(rules(found), ["source-unzoned"], rogue)
        ok = make_pbx({"BaxterToo": {"products": APP_PRODUCTS, "sources": ["Frame/UI/Card.swift", "Packages/BaxterVoiceEngine/Sources/X/Y.swift"]},
                       "BaxterTooRestricted": {"products": APP_PRODUCTS}, "CaptureWitnessObservation": {"products": APP_PRODUCTS}})
        self.assertEqual(run({"BaxterToo.xcodeproj/project.pbxproj": ok}), [])

    def test_group_relative_source_paths_are_resolved_before_judging_them(self):
        pbx = ("// !$*UTF8*$!\n{ objects = {\n"
               "T1 = {isa = PBXNativeTarget; name = BaxterToo; packageProductDependencies = (); buildPhases = (SP);};\n"
               "SP = {isa = PBXSourcesBuildPhase; files = (B1, B2);};\n"
               "B1 = {isa = PBXBuildFile; fileRef = F1;}; B2 = {isa = PBXBuildFile; fileRef = F2;};\n"
               "F1 = {isa = PBXFileReference; path = A.swift; sourceTree = \"<group>\";};\n"
               "F2 = {isa = PBXFileReference; path = B.swift; sourceTree = \"<group>\";};\n"
               "G1 = {isa = PBXGroup; path = Frame; sourceTree = \"<group>\"; children = (G2, F1);};\n"
               "G2 = {isa = PBXGroup; path = UI; sourceTree = \"<group>\"; children = ();};\n"
               "G3 = {isa = PBXGroup; path = scripts; sourceTree = \"<group>\"; children = (F2);};\n"
               "}; rootObject = T1; }\n")
        project = arch_check.pbxproj.parse(pbx)
        self.assertEqual(arch_check.pbxproj.compiled_sources(project, "BaxterToo"), ["Frame/A.swift", "scripts/B.swift"])

    def test_the_real_project_file_parses_and_the_real_tree_facts_are_what_the_policy_names(self):
        repo = HERE.parent.parent
        project_file = repo / "BaxterToo.xcodeproj" / "project.pbxproj"
        if not project_file.exists():
            self.skipTest("not inside the repository checkout")
        project = arch_check.pbxproj.parse(project_file.read_text())
        policy = json.loads(POLICY.read_text())
        for target in policy["dependencies"]["app_targets"]:
            self.assertIn(target, arch_check.pbxproj.native_targets(project))
        self.assertIn("Packages/BaxterMiddlewareKernel", arch_check.pbxproj.local_package_paths(project))


if __name__ == "__main__":
    unittest.main()
