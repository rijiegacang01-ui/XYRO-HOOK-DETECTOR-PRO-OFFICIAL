# XYRO HOOK DETECTOR PRO — Android

Native Kotlin Android app prototype adapted from the uploaded `xyro.py` static-scanner concept.

## What it does
- Uses Android's document picker so the user chooses a source file explicitly.
- Scans the selected text against a small set of defensive heuristic signatures.
- Does not execute the selected file, upload scan contents, or access other apps.
- Includes a harmless text-only demo scan.

**Limitations:** this is a starter implementation, not a full port of every Python rule. Regex matches can be false positives or miss threats. It scans one selected file at a time, not entire folders or APK internals. The included APK is a debug build, not a Play Store release.

## Build on GitHub using a phone
1. On GitHub, create a new repository named `xyro-hook-detector-pro`. Public or private is your choice.
2. Upload all files from this project, preserving folders, to the repository's `main` branch. GitHub mobile: repository → `Add file` → `Upload files` (or use github.com in your browser).
3. Open **Actions**. If prompted, enable workflows. Run **Build Android APK** via **Run workflow**, or push a commit to `main`.
4. Open the completed workflow run. Download `XYRO-HOOK-DETECTOR-PRO-debug` under Artifacts. A release named `build-N` is also created on pushes to `main`.
5. On Android, open the downloaded APK and follow the install prompt. Only install APKs you built or trust.

## Optional Telegram delivery
1. Create your own bot with Telegram's official `@BotFather`; keep its token private.
2. Send a message to the bot, then obtain your chat ID using a trusted method. For a group, add the bot and use the group's chat ID.
3. In GitHub repository **Settings → Secrets and variables → Actions → New repository secret**, add:
   - `TELEGRAM_BOT_TOKEN` = bot token
   - `TELEGRAM_CHAT_ID` = your numeric chat ID (or group ID)
4. Run the workflow again. It sends the APK as a document to that chat.
5. Do not put bot tokens in source code, README, commits, or screenshots. Anyone with the token can control the bot; rotate it immediately if exposed.

## Manual local build
Requires JDK 17 and Gradle 8.9:
```sh
gradle assembleDebug
```
APK output:
`app/build/outputs/apk/debug/app-debug.apk`

## Safety
The app has no Internet permission and no background collection. Telegram upload is performed by GitHub Actions from the build runner only when repository secrets are configured. Never upload private source files or credentials in scan reports.
