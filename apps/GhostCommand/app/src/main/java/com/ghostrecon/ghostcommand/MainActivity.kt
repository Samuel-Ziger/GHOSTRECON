package com.ghostrecon.ghostcommand

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                GhostCommandApp()
            }
        }
    }
}

@Composable
private fun GhostCommandApp() {
    val context = LocalContext.current as Activity
    val prefs = remember { context.getSharedPreferences("ghostcommand", Activity.MODE_PRIVATE) }
    var baseUrl by remember { mutableStateOf("") }
    var apiKey by remember { mutableStateOf("") }
    var commandKey by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Idle") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        baseUrl = prefs.getString("baseUrl", "") ?: ""
        apiKey = prefs.getString("apiKey", "") ?: ""
        commandKey = prefs.getString("commandKey", "") ?: ""
        target = prefs.getString("target", "") ?: ""
    }

    suspend fun call(method: String, path: String, body: JSONObject? = null): String {
        return withContext(Dispatchers.IO) {
            val root = baseUrl.trim().trimEnd('/')
            val payload = (body ?: JSONObject()).toString().toRequestBody("application/json; charset=utf-8".toMediaType())
            val builder = Request.Builder()
                .url(root + path)
                .header("X-API-Key", apiKey.trim())
                .header("X-GhostCommand-Key", commandKey.trim())
            val request = when (method) {
                "GET" -> builder.get().build()
                else -> builder.post(payload).build()
            }
            OkHttpClient().newCall(request).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful) "HTTP ${response.code}: $text" else text
            }
        }
    }

    fun save() {
        prefs.edit()
            .putString("baseUrl", baseUrl.trim())
            .putString("apiKey", apiKey.trim())
            .putString("commandKey", commandKey.trim())
            .putString("target", target.trim())
            .apply()
    }

    suspend fun execute(label: String, block: suspend () -> String) {
        busy = true
        status = "$label..."
        try {
            save()
            status = block()
        } catch (e: Exception) {
            status = e.message ?: "Erro"
        } finally {
            busy = false
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("GhostCommand", style = MaterialTheme.typography.headlineMedium)
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("VPS URL") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it },
                label = { Text("GHOSTRECON API Key") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = commandKey,
                onValueChange = { commandKey = it },
                label = { Text("GhostCommand Key") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = target,
                onValueChange = { target = it },
                label = { Text("Domain") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(enabled = !busy, onClick = {
                    scope.launch {
                        execute("Run") {
                            call("POST", "/api/ghostcommand/recon", JSONObject().put("target", target.trim()))
                        }
                    }
                }) {
                    Text("Run")
                }
                Button(enabled = !busy, onClick = {
                    scope.launch {
                        execute("Status") { call("GET", "/api/ghostcommand/status") }
                    }
                }) {
                    Text("Status")
                }
                Button(enabled = !busy, onClick = {
                    scope.launch {
                        execute("Close") { call("POST", "/api/ghostcommand/gate/close") }
                    }
                }) {
                    Text("Close")
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(status, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
