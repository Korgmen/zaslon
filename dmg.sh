#!/bin/sh
# Собирает build/Zaslon-<версия>.dmg: Zaslon.app и ярлык на «Программы» для установки перетаскиванием.
set -eu
cd "$(dirname "$0")"

./build.sh
VER=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Info.plist)
STAGE=build/dmg
DMG="build/Zaslon-$VER.dmg"

rm -rf "$STAGE"
mkdir -p "$STAGE"
ditto build/Zaslon.app "$STAGE/Zaslon.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
# UDZO открывается на любой macOS. hdiutil create на macOS 26+ устарел, там есть diskutil image.
if diskutil image create from 2>&1 | grep -q -- '--volumeName'; then
  diskutil image create from --format UDZO --volumeName "Zaslon $VER" "$STAGE" "$DMG" >/dev/null
else
  hdiutil create -volname "Zaslon $VER" -srcfolder "$STAGE" -format UDZO -ov "$DMG" >/dev/null
fi
rm -rf "$STAGE"
echo "Готово: $(pwd)/$DMG"
