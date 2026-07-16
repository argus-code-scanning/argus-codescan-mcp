from __future__ import annotations

from pathlib import Path

from argus_languages import scan_directory


def test_finds_dart_cleartext_http(tmp_path: Path) -> None:
    src = tmp_path / "lib" / "api.dart"
    src.parent.mkdir()
    src.write_text('final url = "http://api.example.com/v1/users";\n')
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "dart-cleartext-http" for f in result.findings)


def test_finds_dart_weak_hash(tmp_path: Path) -> None:
    src = tmp_path / "lib" / "crypto.dart"
    src.parent.mkdir()
    src.write_text("import 'package:crypto/crypto.dart';\nfinal d = md5.convert(bytes);\n")
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "dart-weak-hash" for f in result.findings)


def test_finds_flutter_android_debuggable(tmp_path: Path) -> None:
    manifest = tmp_path / "android" / "app" / "src" / "main" / "AndroidManifest.xml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        '<application android:debuggable="true" android:label="app"></application>\n'
    )
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "flutter-android-debuggable" for f in result.findings)


def test_finds_flutter_ios_ats_disabled(tmp_path: Path) -> None:
    plist = tmp_path / "ios" / "Runner" / "Info.plist"
    plist.parent.mkdir(parents=True)
    plist.write_text(
        "<dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n"
    )
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "flutter-ios-arbitrary-loads" for f in result.findings)


def test_skips_generated_dart_files(tmp_path: Path) -> None:
    src = tmp_path / "lib" / "model.g.dart"
    src.parent.mkdir()
    src.write_text('const apiKey = "hardcoded-secret-key-12345";\n')
    result = scan_directory(tmp_path)
    assert not any(f.file.endswith("model.g.dart") for f in result.findings)
