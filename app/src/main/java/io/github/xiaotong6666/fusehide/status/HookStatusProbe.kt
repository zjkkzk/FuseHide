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

package io.github.xiaotong6666.fusehide.status

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference

class HookStatusProbe(
    private val context: Context,
    private val onTimeout: () -> Unit,
    private val onStarted: (WeakReference<Binder>, Thread) -> Unit,
) {
    private val appContext = context.applicationContext ?: context

    fun start() {
        val binder = Binder()
        val referenceQueue = ReferenceQueue<Binder>()
        val binderReference = WeakReference(binder, referenceQueue)

        val intent = Intent(ACTION_GET_STATUS).setPackage(APP_PACKAGE)
        intent.putExtra("EXTRA_PENDING_INTENT", PendingIntent.getBroadcast(context, 1, intent, 67108864))
        intent.extras?.putBinder("EXTRA_BINDER", binder)

        MEDIA_PROVIDER_PACKAGES.forEach { packageName ->
            intent.setPackage(packageName)
            Log.d("FuseHide", "send GET_STATUS to ${intent.`package`}")
            appContext.sendBroadcast(intent)
        }

        val statusThread = Thread { waitForBinderRelease(referenceQueue) }
        statusThread.start()
        onStarted(binderReference, statusThread)
    }

    private fun waitForBinderRelease(referenceQueue: ReferenceQueue<Binder>) {
        try {
            Thread.sleep(2000L)
            Runtime.getRuntime().gc()
            Log.d("FuseHide", "polling ref ...")
            Log.d("FuseHide", "polled = ${referenceQueue.remove()}")
            Handler(Looper.getMainLooper()).post(onTimeout)
        } catch (_: InterruptedException) {
            Log.d("FuseHide", "return")
        }
    }

    companion object {
        private const val APP_PACKAGE = "io.github.xiaotong6666.fusehide"
        const val ACTION_SET_STATUS = "$APP_PACKAGE.SET_STATUS"
        private const val ACTION_GET_STATUS = "$APP_PACKAGE.GET_STATUS"

        val MEDIA_PROVIDER_PACKAGES = listOf(
            "com.google.android.providers.media.module",
            "com.android.providers.media.module",
        )

        fun registerReceiverFlags(): Int = if (android.os.Build.VERSION.SDK_INT >= 33) Context.RECEIVER_EXPORTED else 0
    }
}
