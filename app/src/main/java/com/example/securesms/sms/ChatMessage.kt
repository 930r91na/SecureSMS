package com.example.securesms.sms

data class ChatMessage(
    val content: String,
    val isFromMe: Boolean,
    val timestamp: Long = System.currentTimeMillis()
)