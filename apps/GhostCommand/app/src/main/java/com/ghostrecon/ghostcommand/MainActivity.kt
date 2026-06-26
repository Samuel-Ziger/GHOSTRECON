package com.ghostrecon.ghostcommand

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
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
    val scope = rememberCoroutineScope()
    val http = remember { OkHttpClient() }

    var baseUrl by remember { mutableStateOf("") }
    var apiKey by remember { mutableStateOf("") }
    var commandKey by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    var setupBlob by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Pronto") }
    var busy by remember { mutableStateOf(false) }
    var showConfig by remember { mutableStateOf(true) }

    fun configIsReady(): Boolean {
        return baseUrl.trim().isNotEmpty() && apiKey.trim().isNotEmpty() && commandKey.trim().isNotEmpty()
    }

    fun saveConfig() {
        prefs.edit()
            .putString("baseUrl", baseUrl.trim())
            .putString("apiKey", apiKey.trim())
            .putString("commandKey", commandKey.trim())
            .putString("target", target.trim())
            .apply()
        showConfig = !configIsReady()
        status = if (configIsReady()) "Configuracao salva" else "Complete a configuracao"
    }

    LaunchedEffect(Unit) {
        baseUrl = prefs.getString("baseUrl", "") ?: ""
        apiKey = prefs.getString("apiKey", "") ?: ""
        commandKey = prefs.getString("commandKey", "") ?: ""
        target = prefs.getString("target", "") ?: ""
        showConfig = !(baseUrl.isNotBlank() && apiKey.isNotBlank() && commandKey.isNotBlank())
    }

    fun importConfig(raw: String): String {
        val cleaned = raw.trim()
            .lines()
            .map { it.trim() }
            .firstOrNull { it.startsWith("GHOSTCOMMAND_CONFIG=") }
            ?.substringAfter("=")
            ?: cleanedValue(raw)

        val jsonText = if (cleaned.trim().startsWith("{")) {
            cleaned
        } else {
            val bytes = Base64.decode(cleaned, Base64.URL_SAFE or Base64.NO_WRAP)
            String(bytes, Charsets.UTF_8)
        }
        val json = JSONObject(jsonText)
        baseUrl = json.getString("baseUrl")
        apiKey = json.getString("ghostreconApiKey")
        commandKey = json.getString("ghostCommandKey")
        saveConfig()
        return "Configuracao importada"
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
            http.newCall(request).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful) "HTTP ${response.code}: $text" else text
            }
        }
    }

    suspend fun execute(label: String, block: suspend () -> String) {
        if (!configIsReady()) {
            showConfig = true
            status = "Configure a VPS antes"
            return
        }
        busy = true
        status = "$label..."
        try {
            prefs.edit().putString("target", target.trim()).apply()
            status = block()
        } catch (e: Exception) {
            status = e.message ?: "Erro"
        } finally {
            busy = false
        }
    }

    Surface(Modifier.fillMaxSize(), color = Color(0xFF0B1020)) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(Color(0xFF10182D), Color(0xFF0B1020), Color(0xFF121212)),
                    ),
                ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Header(configured = configIsReady(), onEdit = { showConfig = true })

                if (showConfig) {
                    ConfigPanel(
                        baseUrl = baseUrl,
                        apiKey = apiKey,
                        commandKey = commandKey,
                        setupBlob = setupBlob,
                        onBaseUrl = { baseUrl = it },
                        onApiKey = { apiKey = it },
                        onCommandKey = { commandKey = it },
                        onSetupBlob = { setupBlob = it },
                        onImport = {
                            try {
                                status = importConfig(setupBlob)
                            } catch (e: Exception) {
                                status = "Import falhou: ${e.message}"
                            }
                        },
                        onSave = { saveConfig() },
                    )
                }

                CommandPanel(
                    target = target,
                    status = status,
                    busy = busy,
                    configReady = configIsReady(),
                    onTarget = { target = it },
                    onRun = {
                        scope.launch {
                            execute("Disparando recon") {
                                call("POST", "/api/ghostcommand/recon", JSONObject().put("target", target.trim()))
                            }
                        }
                    },
                    onStatus = {
                        scope.launch {
                            execute("Consultando status") { call("GET", "/api/ghostcommand/status") }
                        }
                    },
                    onClose = {
                        scope.launch {
                            execute("Fechando comandos") { call("POST", "/api/ghostcommand/gate/close") }
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun Header(configured: Boolean, onEdit: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("GhostCommand", color = Color.White, style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            Text(
                if (configured) "VPS configurada" else "Configuracao pendente",
                color = if (configured) Color(0xFF8EF0B0) else Color(0xFFFFD166),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onEdit) {
                Text("Editar", color = Color(0xFF9CCBFF))
            }
        }
    }
}

@Composable
private fun ConfigPanel(
    baseUrl: String,
    apiKey: String,
    commandKey: String,
    setupBlob: String,
    onBaseUrl: (String) -> Unit,
    onApiKey: (String) -> Unit,
    onCommandKey: (String) -> Unit,
    onSetupBlob: (String) -> Unit,
    onImport: () -> Unit,
    onSave: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F7FB)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Setup da VPS", color = Color(0xFF111827), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                value = setupBlob,
                onValueChange = onSetupBlob,
                label = { Text("Cole GHOSTCOMMAND_CONFIG") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
            )
            OutlinedButton(onClick = onImport, modifier = Modifier.fillMaxWidth()) {
                Text("Importar configuracao")
            }
            Spacer(Modifier.height(2.dp))
            OutlinedTextField(
                value = baseUrl,
                onValueChange = onBaseUrl,
                label = { Text("VPS URL") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = onApiKey,
                label = { Text("GHOSTRECON API Key") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = commandKey,
                onValueChange = onCommandKey,
                label = { Text("GhostCommand Key") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Button(onClick = onSave, modifier = Modifier.fillMaxWidth()) {
                Text("Salvar configuracao")
            }
        }
    }
}

@Composable
private fun CommandPanel(
    target: String,
    status: String,
    busy: Boolean,
    configReady: Boolean,
    onTarget: (String) -> Unit,
    onRun: () -> Unit,
    onStatus: () -> Unit,
    onClose: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F7FB)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Alvo", color = Color(0xFF111827), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                value = target,
                onValueChange = onTarget,
                label = { Text("Dominio") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            )
            Button(
                enabled = !busy && configReady && target.trim().isNotEmpty(),
                onClick = onRun,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1D4ED8)),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (busy) "Rodando..." else "Rodar agora")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(enabled = !busy && configReady, onClick = onStatus, modifier = Modifier.weight(1f)) {
                    Text("Status")
                }
                OutlinedButton(enabled = !busy && configReady, onClick = onClose, modifier = Modifier.weight(1f)) {
                    Text("Fechar")
                }
            }
            Text("Retorno", color = Color(0xFF374151), fontWeight = FontWeight.SemiBold)
            Text(status, color = Color(0xFF111827), style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun cleanedValue(raw: String): String {
    return raw.trim()
        .removePrefix("GHOSTCOMMAND_CONFIG=")
        .trim()
}
