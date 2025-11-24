# SecureSMS: TLS-Style Encrypted SMS Channel

SecureSMS is an Android application that establishes a secure, encrypted communication channel over standard SMS. It implements a custom TLS-like handshake protocol to negotiate session keys, authenticate parties, and ensure message confidentiality.

---

## Overview

This application demonstrates end-to-end encryption over SMS by implementing a protocol similar to TLS/SSL. All cryptographic operations are performed locally on the device, with no external servers involved.



https://github.com/user-attachments/assets/50913fd9-dd28-47d4-929f-a5c997ba0a92


---

## Cryptographic Suite

### Algorithms

- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH) using the P-256 (secp256r1) curve
- **Authentication**: RSA-2048 signatures with self-signed certificates
- **Symmetric Encryption**: AES-256-GCM (Galois/Counter Mode) for authenticated encryption
- **Hashing & Key Derivation**: SHA-256 and HMAC-SHA256

### Security Properties

- **Confidentiality**: Messages are encrypted with AES-256-GCM
- **Authenticity**: RSA signatures verify the identity of communicating parties
- **Perfect Forward Secrecy**: Ephemeral ECDH keys ensure session keys cannot be recovered from long-term keys

---

## Protocol Design

### Phase 1: The Handshake

The application performs a 3-way handshake to establish a secure session before any messages can be sent.

#### Step 1: Client Hello (Alice → Bob)

Alice initiates the handshake:
- Generates a random 32-byte nonce (`ClientRandom`)
- Sends `CL_HELLO` containing the nonce and supported cipher suites

#### Step 2: Server Hello (Bob → Alice)

Bob responds with:
- A random 32-byte nonce (`ServerRandom`)
- An ephemeral ECDH key pair
- A self-signed certificate containing his RSA identity key
- A signature over the hash of: `ClientRandom || ServerRandom || ECDH_Public_Key`

Sends `SV_HELLO` with the random, certificate, ephemeral public key, and signature.

#### Step 3: Client Key Exchange (Alice → Bob)

Alice completes the handshake:
- Verifies Bob's certificate and signature
- Generates her own ephemeral ECDH key pair
- Computes the shared secret using ECDH: `Alice_Private + Bob_Public`
- Signs the handshake parameters with her RSA key

Sends `CL_KEY_EX` containing her certificate, ephemeral public key, and signature.

### Phase 2: Key Derivation

Both parties independently derive session keys using the Key Derivation Function (KDF):
```
Pre-Master Secret = ECDH(Alice_Private, Bob_Public)
Master Secret = HMAC-SHA256(Pre-Master, "master secret", ClientRandom || ServerRandom)
Session Keys = HMAC-SHA256(Master Secret, "key expansion", ServerRandom || ClientRandom)
```

The output is split into four keys:
- `ClientEncryptKey`
- `ServerEncryptKey`
- `ClientMACKey`
- `ServerMACKey`

### Phase 3: Encrypted Transport

Once the handshake is complete:
- Messages are encrypted using AES-256-GCM with the appropriate session key
- Encrypted payloads are Base64 encoded and sent as: `MSG:<Base64_Data>`
- The receiver decrypts using the corresponding session key

---

## Installation & Setup

### Prerequisites

- Android Studio (latest version recommended)
- Android SDK (API 33 or higher)
- Two Android emulators or devices for testing
- Python 3.x (for the relay script)
- ADB (Android Debug Bridge) in system PATH

### Steps

1. **Clone the Repository**
```bash
   git clone <repository-url>
   cd SecureSMS
```

2. **Open in Android Studio**
   - Open the project folder
   - Wait for Gradle to sync dependencies

3. **Grant Permissions**
   
   The app requires `SEND_SMS` and `RECEIVE_SMS` permissions. On Android Emulators (API 33+), you must manually grant these:
```
   Settings → Apps → SecureSMS → Permissions → SMS → Allow
```

4. **Build and Install**
   - Build the project in Android Studio
   - Install on two emulator instances or devices

---

## Testing with Emulator Relay

Due to limitations in the Android Emulator's cellular network simulation, emulators cannot send SMS directly to each other. To work around this, we use a Python relay script that acts as a virtual "cell tower."

### Step 1: Start the Relay Tower

Ensure Python is installed and ADB is in your system PATH. Run the relay script:
```bash
python relay_sms.py
```

You should see:
```
=== SECURE SMS SMART RELAY TOWER ===
Listening for SMS traffic between emulators...
```

### Step 2: Launch Two Emulators

Start two emulator instances (e.g., ports 5554 and 5556):
```bash
emulator -avd <avd_name_1> &
emulator -avd <avd_name_2> &
```

Ensure the SecureSMS app is open and visible on both screens.

### Step 3: Initiate the Connection

**On Emulator 5554 (Sender):**
1. Enter target port: `5556`
2. Tap the lock icon to initiate the TLS handshake

**Watch the Terminal:**
- The Python script detects the outgoing SMS from 5554
- Executes ADB commands to deliver messages to 5556
- Relays replies back to 5554

**Check the UI:**
- Both devices display green logs indicating handshake progress
- Final status: **"SECURE HANDSHAKE COMPLETE"**

### Step 4: Send Encrypted Messages

**On Emulator 5554:**
1. Type a message in the input field
2. Click **Send**
3. Result: Blue bubble appears on sender, gray bubble on receiver

**To Reply from 5556:**
1. Change the target field to `5554`
2. Type your message and click **Send**

---

## Architecture

### Key Components

- **CryptoEngine**: Handles all cryptographic operations (ECDH, RSA, AES-GCM, KDF)
- **HandshakeManager**: Orchestrates the TLS-like handshake protocol
- **MessageEncryptor**: Encrypts and decrypts message payloads
- **SMSManager**: Handles sending and receiving SMS messages
- **UI Components**: Chat interface with message bubbles and status indicators

### Message Flow
```
[Alice] → ClientHello → [Bob]
[Alice] ← ServerHello ← [Bob]
[Alice] → ClientKeyEx → [Bob]
        ↓ Key Derivation ↓
[Alice] ⟷ Encrypted MSG ⟷ [Bob]
```

---

## Security Considerations

### Strengths

✓ End-to-end encryption with AES-256-GCM  
✓ Perfect forward secrecy via ephemeral ECDH keys  
✓ Authenticated encryption prevents tampering  
✓ Self-signed certificates for identity verification  

### Limitations

⚠ **Self-Signed Certificates**: No certificate authority validation (vulnerable to MITM without pre-shared trust)  
⚠ **SMS Transport**: SMS is an insecure channel for handshake messages (metadata visible to carriers)  
⚠ **No Key Persistence**: Session keys are not saved; handshake required per session  
⚠ **Demo Application**: Not audited for production use  

---

## Troubleshooting

### Permissions Not Granted

**Issue**: App crashes or cannot send/receive SMS  
**Solution**: Manually grant SMS permissions in device settings

### Emulators Cannot Communicate

**Issue**: Messages not being delivered between emulators  
**Solution**: Ensure the relay script is running and ADB is properly configured

### Handshake Fails

**Issue**: Handshake does not complete  
**Solution**: 
- Check that both devices have the app open
- Verify correct target port numbers
- Review logs for cryptographic errors

### Relay Script Errors

**Issue**: Python script fails to detect SMS  
**Solution**:
- Ensure ADB is in system PATH: `adb version`
- Check emulator port numbers: `adb devices`
- Restart the relay script

---

## Development

### Building from Source
```bash
./gradlew assembleDebug
```

### Running Tests
```bash
./gradlew test
```

### Code Structure
```
app/
├── src/
│   ├── main/
│   │   ├── java/com/example/securesms/
│   │   │   ├── crypto/           # Cryptographic operations
│   │   │   ├── protocol/         # Handshake protocol logic
│   │   │   ├── ui/               # User interface components
│   │   │   └── utils/            # Helper utilities
│   │   └── res/                  # Resources (layouts, strings)
│   └── test/                     # Unit tests
└── build.gradle                  # Build configuration
```

---

## License

This project is provided as-is for educational purposes. Use at your own risk.

---

## Acknowledgments

This application is inspired by the TLS/SSL protocol and demonstrates how modern cryptographic techniques can be applied to SMS communication.

---

## Contact

For questions, issues, or contributions, please open an issue on the project repository.
