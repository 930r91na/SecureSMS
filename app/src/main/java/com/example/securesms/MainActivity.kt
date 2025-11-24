package com.example.securesms

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.example.securesms.ui.screens.RSATestScreen
import com.example.securesms.ui.theme.SecureSMSTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SecureSMSTheme {
                SecureSMSApp()
            }
        }
    }
}

@Composable
fun SecureSMSApp() {
    var currentDestination by rememberSaveable { mutableStateOf(AppDestinations.RSA_TEST) }

    NavigationSuiteScaffold(
        navigationSuiteItems = {
            AppDestinations.entries.forEach {
                item(
                    icon = {
                        Icon(
                            it.icon,
                            contentDescription = it.label
                        )
                    },
                    label = { androidx.compose.material3.Text(it.label) },
                    selected = it == currentDestination,
                    onClick = { currentDestination = it }
                )
            }
        }
    ) {
        Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
            when (currentDestination) {
                AppDestinations.RSA_TEST -> {
                    RSATestScreen()
                }
                AppDestinations.SEND_SMS -> {
                    // TODO: Implement SendSMSScreen
                    androidx.compose.material3.Text(
                        text = "Send SMS Screen - Coming Soon",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
                AppDestinations.SETTINGS -> {
                    // TODO: Implement Settings
                    androidx.compose.material3.Text(
                        text = "Settings Screen - Coming Soon",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

enum class AppDestinations(
    val label: String,
    val icon: ImageVector,
) {
    RSA_TEST("RSA Test", Icons.Default.Lock),
    SEND_SMS("Send SMS", Icons.Default.Send),
    SETTINGS("Settings", Icons.Default.Settings),
}