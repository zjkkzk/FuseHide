/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.xiaotong6666.fusehide.debug

import android.content.pm.PackageManager
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.nio.charset.StandardCharsets

object PathDebugActions {
    fun defaultPath(): String = "/storage/emulated/0/xinhao"

    fun modeLabel(mode: Int): String = when (mode) {
        0 -> "Stat"
        1 -> "Access"
        2 -> "List"
        3 -> "Open"
        4 -> "GetCon"
        5 -> "Create"
        6 -> "Mkdir"
        7 -> "Rename(Move)"
        8 -> "Rmdir"
        9 -> "Unlink"
        else -> "Unknown"
    }

    fun runPathCheck(mode: Int, pathText: String, pathText2: String): String {
        val rawPath = PathDebugText.unescapeUnicodeLiterals(pathText) ?: return ""
        val displayPath = PathDebugText.escapeNonAscii(rawPath)
        return try {
            when (mode) {
                0 -> "Stat $displayPath -> OK\n${StructStatFormatter.format(Os.stat(rawPath))}\n"

                1 -> {
                    Os.access(rawPath, OsConstants.F_OK)
                    "Access $displayPath -> OK\n"
                }

                2 -> {
                    val files = File(rawPath).list()
                    if (files == null) {
                        "List $displayPath -> None\n"
                    } else {
                        buildString {
                            append("List $displayPath -> ${files.size} file(s)\n")
                            files.forEach { append(it).append('\n') }
                        }
                    }
                }

                3 -> {
                    val fd = Os.open(rawPath, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
                    try {
                        Os.close(fd)
                    } catch (th: Throwable) {
                        Log.e("FuseHide", "could not close??", th)
                    }
                    "Open $displayPath -> OK\n"
                }

                4 -> {
                    val selinuxContext = String(Os.getxattr(rawPath, "security.selinux"), StandardCharsets.UTF_8)
                    "GetCon $displayPath -> OK\n$selinuxContext\n"
                }

                5 -> nativeResult("Create", displayPath, Utils.create(rawPath))

                6 -> nativeResult("Mkdir", displayPath, Utils.mkdir(rawPath))

                7 -> {
                    val rawPath2 = PathDebugText.unescapeUnicodeLiterals(pathText2) ?: return ""
                    if (rawPath2.isEmpty()) {
                        "Rename(Move) requires Path 2\n"
                    } else {
                        val displayPath2 = PathDebugText.escapeNonAscii(rawPath2)
                        val res = Utils.rename(rawPath, rawPath2)
                        if (res == 0) {
                            "Rename(Move) $displayPath -> $displayPath2 -> OK\n"
                        } else {
                            "Rename(Move) $displayPath -> $displayPath2 -> ${OsConstants.errnoName(res)}\n"
                        }
                    }
                }

                8 -> nativeResult("Rmdir", displayPath, Utils.rmdir(rawPath))

                9 -> nativeResult("Unlink", displayPath, Utils.unlink(rawPath))

                else -> ""
            }
        } catch (errno: ErrnoException) {
            "${modeLabel(mode)} $displayPath -> ${OsConstants.errnoName(errno.errno)}\n"
        }
    }

    fun runAllPkgCheck(packageManager: PackageManager, pathText: String): String = buildString {
        try {
            val pkgs = packageManager.getInstalledApplications(0)
            if (pkgs.size <= 1) {
                append("Could not get app list, please grant app list permission\n")
                return@buildString
            }
            val appDataPath = PathDebugText.unescapeUnicodeLiterals(pathText).orEmpty()
            if (appDataPath.isEmpty()) {
                append("Please enter a base path first\n")
                return@buildString
            }
            val base = if (appDataPath.endsWith("/")) appDataPath else "$appDataPath/"
            append("Using base path: ${PathDebugText.escapeNonAscii(base)}\n")
            var existCount = 0
            val existPkgs = StringBuilder()
            pkgs.forEach { pkg ->
                try {
                    Os.stat(base + pkg.packageName)
                    existCount++
                    existPkgs.append(pkg.packageName).append("\n")
                } catch (_: ErrnoException) {
                }
            }
            append("Detected $existCount/${pkgs.size} packages\n")
            append(existPkgs)
        } catch (t: Throwable) {
            append("Error: ${t.message}\n")
        }
    }

    private fun nativeResult(label: String, displayPath: String, errno: Int): String = if (errno == 0) {
        "$label $displayPath -> OK\n"
    } else {
        "$label $displayPath -> ${OsConstants.errnoName(errno)}\n"
    }
}
