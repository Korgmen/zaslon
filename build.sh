#!/bin/sh
# Собирает build/Zaslon.app, универсальный бинарник (Apple Silicon и Intel). Нужен Xcode.
set -eu
cd "$(dirname "$0")"

SDK=$(xcrun --sdk macosx --show-sdk-path)
SWIFTC=$(xcrun --sdk macosx --find swiftc)
APP=build/Zaslon.app

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
for ARCH in arm64 x86_64; do
  "$SWIFTC" -O -sdk "$SDK" -swift-version 5 -target "$ARCH-apple-macos13" \
    main.swift -o "build/Zaslon-$ARCH"
done
lipo -create build/Zaslon-arm64 build/Zaslon-x86_64 -output "$APP/Contents/MacOS/Zaslon"
rm build/Zaslon-arm64 build/Zaslon-x86_64
cp Info.plist "$APP/Contents/"
cp AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP"
echo "Готово: $(pwd)/$APP"
