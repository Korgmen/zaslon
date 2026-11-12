#!/bin/sh
# Собирает build/Zaslon.app. Нужен Xcode (или Command Line Tools).
set -eu
cd "$(dirname "$0")"

SDK=$(xcrun --sdk macosx --show-sdk-path)
SWIFTC=$(xcrun --sdk macosx --find swiftc)
APP=build/Zaslon.app

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
"$SWIFTC" -O -sdk "$SDK" -swift-version 5 -target "$(uname -m)-apple-macos13" \
  main.swift -o "$APP/Contents/MacOS/Zaslon"
cp Info.plist "$APP/Contents/"
cp AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP"
echo "Готово: $(pwd)/$APP"
