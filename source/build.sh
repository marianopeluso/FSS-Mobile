#!/usr/bin/env bash
# Builds FSS Mobile without Gradle/Android Studio.
# Tools (all downloadable from GitHub): JDK 17+, android.jar API 34 (Sable/android-platforms),
# aapt2 (from the Apktool release jar), D8 (bundled in jadx-all.jar).
#
# Since 0.5.3 this script produces an UNSIGNED APK only. The release signature is applied on the
# maintainer's PC with the release key, which is never stored in this repository.
set -euo pipefail
cd "$(dirname "$0")"
: "${JDK:?set JDK=/path/to/jdk17}" "${ANDROID_JAR:?}" "${AAPT2:?}" "${D8_JAR:?}"
VERSION_NAME=0.5.3; VERSION_CODE=18
OUT=build; rm -rf "$OUT"; mkdir -p "$OUT/res" "$OUT/gen" "$OUT/classes" "$OUT/dex"
"$AAPT2" compile --dir res -o "$OUT/res"
"$AAPT2" link -I "$ANDROID_JAR" --manifest AndroidManifest.xml -o "$OUT/base.apk" \
  --java "$OUT/gen" --min-sdk-version 26 --target-sdk-version 34 \
  --version-code $VERSION_CODE --version-name $VERSION_NAME "$OUT"/res/*.flat
# Only the app sources are listed; zxing is on the sourcepath, so javac compiles just the
# zxing classes the app actually uses (QR code only).
find src "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
"$JDK/bin/javac" -nowarn -Xlint:-options -encoding UTF-8 --release 8 \
  -classpath "$ANDROID_JAR" -sourcepath third_party/zxing-core-3.5.3 -implicit:class \
  -d "$OUT/classes" @"$OUT/sources.txt"
find "$OUT/classes" -name '*.class' > "$OUT/classes.txt"
"$JDK/bin/java" -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api 26 \
  --lib "$ANDROID_JAR" --output "$OUT/dex" @"$OUT/classes.txt"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && "$JDK/bin/jar" uf ../unsigned.apk classes.dex)
cp "$OUT/unsigned.apk" "../FSS_Mobile_${VERSION_NAME}_unsigned.apk"
echo "Built (unsigned): ../FSS_Mobile_${VERSION_NAME}_unsigned.apk"
