package com.xyro.hookdetector

import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.graphics.Typeface
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.BufferedReader
import java.io.InputStreamReader

class MainActivity : Activity() {
    private val green = 0xFF00FF88.toInt()
    private val bg = 0xFF0B0E14.toInt()
    private val panel = 0xFF151B25.toInt()
    private val cyan = 0xFF00F0FF.toInt()
    private lateinit var output: TextView
    private val PICK_FILE = 411

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(22, 28, 22, 20)
            setBackgroundColor(bg)
        }
        val scroller = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val title = TextView(this).apply {
            text = "XYRO // HOOK DETECTOR PRO"
            textSize = 23f; setTextColor(green); typeface = Typeface.DEFAULT_BOLD
        }
        val subtitle = TextView(this).apply {
            text = "OFFLINE STATIC CODE SCANNER  •  v1.0"
            textSize = 12f; setTextColor(cyan); setPadding(0, 8, 0, 20)
        }
        output = TextView(this).apply {
            text = "Ready.\n\nChoose a source-code file to scan. XYRO reads text only and does not execute or upload inspected files.\n\nNote: detections are heuristic indicators, not proof of malware."
            textSize = 14f; setTextColor(0xFFE5EAF2.toInt()); setPadding(16,16,16,16); setBackgroundColor(panel)
        }
        content.addView(title); content.addView(subtitle)
        content.addView(makeButton("SCAN SOURCE FILE") {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            startActivityForResult(intent, PICK_FILE)
        })
        content.addView(makeButton("SCAN DEMO SAMPLE") { scanText("demo.py", DEMO) })
        content.addView(makeButton("ABOUT / SAFETY") {
            output.text = "XYRO is a defensive static scanner based on the uploaded xyro.py concept. It checks source text against simple signatures for suspicious hooks, process injection APIs, credential access, obfuscation and embedded secrets.\n\nIt does not execute inspected code, access other apps, collect device data, or send files over the network. False positives and missed detections are possible."
        })
        val gap = TextView(this).apply { text = "\nSCAN REPORT"; setTextColor(green); textSize = 14f; typeface = Typeface.DEFAULT_BOLD; setPadding(0,18,0,8) }
        content.addView(gap); content.addView(output)
        scroller.addView(content)
        page.addView(scroller, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(page)
    }

    private fun makeButton(label: String, action: () -> Unit): Button =
        Button(this).apply {
            text = label; setTextColor(bg); setBackgroundColor(green)
            isAllCaps = false
            setOnClickListener { action() }
            val p = LinearLayout.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT)
            p.setMargins(0, 0, 0, 10)
            layoutParams = p
        }

    @Deprecated("Legacy document picker callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_FILE && resultCode == RESULT_OK) {
            val uri: Uri = data?.data ?: return
            try {
                contentResolver.openInputStream(uri)?.use { stream ->
                    val text = BufferedReader(InputStreamReader(stream)).readText().take(2_000_000)
                    scanText(uri.lastPathSegment ?: "selected file", text)
                } ?: run { output.text = "Could not open selected file." }
            } catch (e: Exception) {
                output.text = "Read error: ${e.message ?: "unknown error"}"
            }
        }
    }

    private data class Rule(val name: String, val severity: String, val regex: Regex, val advice: String)
    private val rules = listOf(
        Rule("Windows low-level input hook", "HIGH", Regex("""SetWindowsHookEx[AW]?\s*\(|WH_KEYBOARD_LL|WH_MOUSE_LL""", RegexOption.IGNORE_CASE), "Review whether global keyboard or mouse interception is expected."),
        Rule("Process memory injection API", "HIGH", Regex("""VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory""", RegexOption.IGNORE_CASE), "Audit process access and remote memory operations."),
        Rule("Potential credential store access", "HIGH", Regex("""Login Data|Cookies\.sqlite|CryptUnprotectData|os_crypt\.decrypt|Local State""", RegexOption.IGNORE_CASE), "Check why browser credential or cookie stores are referenced."),
        Rule("Keyboard listener library", "HIGH", Regex("""pynput\.keyboard|keyboard\.on_press|Listener\s*\(\s*on_press""", RegexOption.IGNORE_CASE), "Confirm user consent and intended input handling."),
        Rule("Hardcoded cloud or bot token", "HIGH", Regex("""AKIA[0-9A-Z]{16}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}|(?:api[_-]?key|bot[_-]?token)\s*=\s*['"][^'"]{12,}['"]""", RegexOption.IGNORE_CASE), "Revoke exposed credentials and load secrets from protected configuration."),
        Rule("Private key header", "HIGH", Regex("""-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----""", RegexOption.IGNORE_CASE), "Remove private keys from source and rotate if exposed."),
        Rule("Suspicious shell execution", "MEDIUM", Regex("""os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\(|Runtime\.getRuntime\(\)\.exec""", RegexOption.IGNORE_CASE), "Inspect command construction and any untrusted input."),
        Rule("Dynamic code evaluation", "MEDIUM", Regex("""\beval\s*\(|\bexec\s*\(|compile\s*\(""", RegexOption.IGNORE_CASE), "Review dynamic execution and validate the origin of supplied code."),
        Rule("Long escaped byte sequence", "MEDIUM", Regex("""(?:\\x[0-9a-fA-F]{2}){12,}"""), "Inspect encoded data; legitimate constants may also match."),
        Rule("Large Base64-like literal", "LOW", Regex("""['"][A-Za-z0-9+/]{120,}={0,2}['"]"""), "Inspect long encoded strings to determine whether they hide payloads.")
    )

    private fun scanText(filename: String, source: String) {
        val hits = mutableListOf<String>()
        val lines = source.lines()
        for ((index, line) in lines.withIndex()) {
            for (rule in rules) {
                if (rule.regex.containsMatchIn(line)) {
                    hits.add("[${rule.severity}] ${rule.name}\nLine ${index + 1}: ${line.trim().take(220)}\nAdvice: ${rule.advice}")
                }
            }
        }
        output.text = buildString {
            append("FILE: $filename\nLINES: ${lines.size}\nFINDINGS: ${hits.size}\n\n")
            if (hits.isEmpty()) append("No configured signatures matched. This does NOT prove the file is safe.")
            else append(hits.joinToString("\n\n────────────────────\n\n"))
            append("\n\n────────────────────\nStatic heuristic only. Manually verify each result.")
        }
        Toast.makeText(this, "Scan complete: ${hits.size} finding(s)", Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val DEMO = """
# Harmless demonstration snippets; scanned as text only
import pynput.keyboard
SetWindowsHookExA(
subprocess.run("example")
"""
    }
}
