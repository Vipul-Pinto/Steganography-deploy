import cv2
import numpy as np
import struct
import hashlib
import io
from flask import (
    Flask,
    request,
    send_file,
    render_template_string,
    flash,
    redirect,
    url_for,
)

app = Flask(__name__)
app.secret_key = "super_secret_stego_key"  # Needed for flash messages

# ==========================================
#  CORE STEGANOGRAPHY LOGIC
# ==========================================


class SteganographyEngine:
    """
    Handles the bit-level manipulation of images to hide and retrieve data.
    """

    HEADER_SIZE = 4  # 4 bytes (32 bits) to store the length of the payload
    SENTINEL = b"##STEGO_CHECK##"  # Magic bytes to verify successful decryption

    @staticmethod
    def _generate_key(password):
        """Generates a 32-byte hash from the password for encryption."""
        return hashlib.sha256(password.encode("utf-8")).digest()

    @staticmethod
    def _xor_encrypt_decrypt(data_bytes, password):
        """
        Symmetric XOR encryption using a hashed password.
        Safe for any byte data (text, emojis, binary).
        """
        if not password:
            return data_bytes

        key = SteganographyEngine._generate_key(password)
        key_len = len(key)
        result = bytearray()

        for i, byte in enumerate(data_bytes):
            result.append(byte ^ key[i % key_len])
        return bytes(result)

    @staticmethod
    def _bytes_to_bits(data_bytes):
        """Generator: Yields bits from bytes."""
        for b in data_bytes:
            for i in range(8):
                yield (b >> (7 - i)) & 1

    @staticmethod
    def _bits_to_bytes(bits):
        """Helper: Converts list of bits back to bytes."""
        chars = []
        for b in range(len(bits) // 8):
            byte = bits[b * 8 : (b + 1) * 8]
            chars.append(int("".join(map(str, byte)), 2))
        return bytes(chars)

    @classmethod
    def encode(cls, image_stream, text, password):
        # 1. Read Image from memory
        file_bytes = np.frombuffer(image_stream.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Could not decode image.")

        # 2. Prepare Payload
        # Prepend SENTINEL so we can verify the password later
        text_bytes = cls.SENTINEL + text.encode("utf-8")
        encrypted_bytes = cls._xor_encrypt_decrypt(text_bytes, password)

        # Create Header (Length of encrypted data)
        data_len = len(encrypted_bytes)
        # Pack as Big-Endian Unsigned Int
        header = struct.pack(">I", data_len)

        full_payload = header + encrypted_bytes

        # 3. Check Capacity
        total_pixels = img.size  # Height * Width * Channels
        required_bits = len(full_payload) * 8

        if required_bits > total_pixels:
            raise ValueError(
                f"Image too small. Need {required_bits} pixels, have {total_pixels}."
            )

        # 4. Embed Bits
        flat_img = img.flatten()
        bit_generator = cls._bytes_to_bits(full_payload)

        idx = 0
        try:
            for bit in bit_generator:
                # Clear LSB then set it to our bit
                flat_img[idx] = (flat_img[idx] & 0xFE) | bit
                idx += 1
        except IndexError:
            pass  # Should be covered by capacity check, but just in case

        # 5. Reconstruct Image
        steg_img = flat_img.reshape(img.shape)

        # Encode back to PNG memory stream
        is_success, buffer = cv2.imencode(".png", steg_img)
        if not is_success:
            raise ValueError("Failed to encode output image.")

        return io.BytesIO(buffer)

    @classmethod
    def decode(cls, image_stream, password):
        # 1. Read Image
        file_bytes = np.frombuffer(image_stream.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Could not decode image.")

        flat_img = img.flatten()

        # 2. Extract Header (First 32 bits)
        header_bits = [flat_img[i] & 1 for i in range(32)]
        header_bytes = cls._bits_to_bytes(header_bits)

        try:
            msg_length = struct.unpack(">I", header_bytes)[0]
        except:
            raise ValueError("Failed to retrieve header. Is this an encoded image?")

        # Sanity check for length
        if msg_length > len(flat_img) // 8:
            raise ValueError(
                "Detected message length is impossibly large. Wrong password or not encoded?"
            )

        # 3. Extract Payload
        payload_bits = []
        start = 32
        end = 32 + (msg_length * 8)

        for i in range(start, end):
            payload_bits.append(flat_img[i] & 1)

        encrypted_bytes = cls._bits_to_bytes(payload_bits)

        # 4. Decrypt
        decrypted_bytes = cls._xor_encrypt_decrypt(encrypted_bytes, password)

        # 5. Verify Sentinel (Password Check)
        if not decrypted_bytes.startswith(cls.SENTINEL):
            raise ValueError(
                "Wrong password provided (or image contains no hidden data)."
            )

        # Strip the sentinel to get actual message
        actual_message_bytes = decrypted_bytes[len(cls.SENTINEL) :]

        return actual_message_bytes.decode("utf-8")


# ==========================================
#  FRONTEND TEMPLATE (HTML/CSS/JS)
# ==========================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StegoCrypt | Universal Image Steganography</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass {
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-gray-900 via-gray-800 to-black min-h-screen text-gray-100 flex flex-col items-center py-10">

    <!-- Header -->
    <div class="text-center mb-10">
        <h1 class="text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400 mb-2">
            <i class="fas fa-user-secret mr-3 text-emerald-400"></i>StegoCrypt
        </h1>
        <p class="text-gray-400">Securely hide text inside images using Bitwise LSB & XOR Encryption</p>
    </div>

    <!-- Main Container -->
    <div class="w-full max-w-4xl p-1">
        
        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <div class="mb-6 space-y-2">
              {% for category, message in messages %}
                <div class="p-4 rounded-lg border {{ 'bg-red-900/50 border-red-500/50 text-red-200' if category == 'error' else 'bg-emerald-900/50 border-emerald-500/50 text-emerald-200' }}">
                    <i class="fas {{ 'fa-exclamation-circle' if category == 'error' else 'fa-check-circle' }} mr-2"></i> {{ message }}
                </div>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}

        <!-- Tabs -->
        <div class="flex justify-center mb-8 bg-gray-800/50 p-1 rounded-xl max-w-md mx-auto border border-gray-700">
            <button onclick="switchTab('encode')" id="btn-encode" class="flex-1 py-2 px-6 rounded-lg font-semibold transition-all bg-emerald-600 text-white shadow-lg shadow-emerald-900/50">
                <i class="fas fa-lock mr-2"></i>Encode
            </button>
            <button onclick="switchTab('decode')" id="btn-decode" class="flex-1 py-2 px-6 rounded-lg font-semibold transition-all text-gray-400 hover:text-white">
                <i class="fas fa-lock-open mr-2"></i>Decode
            </button>
        </div>

        <!-- Encode Section -->
        <div id="encode-panel" class="glass rounded-2xl p-8 shadow-2xl animate-fade-in">
            <form action="/encode" method="post" enctype="multipart/form-data" class="space-y-6">
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <!-- Image Input -->
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300">1. Select Base Image</label>
                        <div class="relative group">
                            <input type="file" name="image" required accept="image/*" class="w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-700 file:text-emerald-400 hover:file:bg-gray-600 cursor-pointer border border-gray-600 rounded-lg p-2 bg-gray-800 focus:outline-none focus:border-emerald-500 transition-colors">
                        </div>
                        <p class="text-xs text-gray-500">Supports PNG, JPG, BMP. Output will be PNG.</p>
                    </div>

                    <!-- Password -->
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300">3. Set Password (Optional)</label>
                        <div class="relative">
                            <i class="fas fa-key absolute left-3 top-3 text-gray-500"></i>
                            <input type="password" name="password" placeholder="Encryption Key" class="w-full bg-gray-800 border border-gray-600 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all">
                        </div>
                    </div>
                </div>

                <!-- Text Area -->
                <div class="space-y-2">
                    <label class="block text-sm font-medium text-gray-300">2. Enter Secret Message</label>
                    <textarea name="text" required rows="5" placeholder="Type your secret message here... supports Emojis 🌍, Kanji 漢字, and standard text." class="w-full bg-gray-800 border border-gray-600 rounded-lg p-4 text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 mono transition-all"></textarea>
                </div>

                <button type="submit" class="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg shadow-lg shadow-emerald-900/50 transition-all transform hover:scale-[1.01] flex items-center justify-center group">
                    <span>Encode & Download Image</span>
                    <i class="fas fa-download ml-2 group-hover:translate-y-1 transition-transform"></i>
                </button>
            </form>
        </div>

        <!-- Decode Section -->
        <div id="decode-panel" class="glass rounded-2xl p-8 shadow-2xl hidden">
            <form action="/decode" method="post" enctype="multipart/form-data" class="space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300">1. Upload Encoded Image</label>
                        <input type="file" name="image" required accept="image/png" class="w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-700 file:text-blue-400 hover:file:bg-gray-600 cursor-pointer border border-gray-600 rounded-lg p-2 bg-gray-800 focus:outline-none focus:border-blue-500 transition-colors">
                        <p class="text-xs text-yellow-500"><i class="fas fa-exclamation-triangle mr-1"></i>Must be the PNG generated by this tool.</p>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300">2. Enter Password</label>
                        <div class="relative">
                            <i class="fas fa-unlock absolute left-3 top-3 text-gray-500"></i>
                            <input type="password" name="password" placeholder="Decryption Key" class="w-full bg-gray-800 border border-gray-600 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all">
                        </div>
                    </div>
                </div>

                <button type="submit" class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg shadow-lg shadow-blue-900/50 transition-all transform hover:scale-[1.01] flex items-center justify-center group">
                    <span>Reveal Secret Message</span>
                    <i class="fas fa-eye ml-2 group-hover:scale-110 transition-transform"></i>
                </button>
            </form>

            <!-- Result Area -->
            {% if result_text %}
            <div class="mt-8 animate-fade-in-up">
                <label class="block text-sm font-medium text-blue-400 mb-2">Decoded Message:</label>
                <div class="relative">
                    <pre class="w-full bg-gray-900 border border-gray-700 rounded-lg p-4 text-emerald-400 mono whitespace-pre-wrap break-words overflow-x-hidden">{{ result_text }}</pre>
                    <button onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)" class="absolute top-2 right-2 text-gray-500 hover:text-white transition-colors p-2" title="Copy">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>
            {% endif %}
        </div>

    </div>

    <script>
        function switchTab(tab) {
            const encodeBtn = document.getElementById('btn-encode');
            const decodeBtn = document.getElementById('btn-decode');
            const encodePanel = document.getElementById('encode-panel');
            const decodePanel = document.getElementById('decode-panel');

            if(tab === 'encode') {
                encodePanel.classList.remove('hidden');
                decodePanel.classList.add('hidden');
                encodeBtn.classList.add('bg-emerald-600', 'text-white', 'shadow-lg');
                encodeBtn.classList.remove('text-gray-400');
                decodeBtn.classList.remove('bg-blue-600', 'text-white', 'shadow-lg');
                decodeBtn.classList.add('text-gray-400');
            } else {
                encodePanel.classList.add('hidden');
                decodePanel.classList.remove('hidden');
                decodeBtn.classList.add('bg-blue-600', 'text-white', 'shadow-lg');
                decodeBtn.classList.remove('text-gray-400');
                encodeBtn.classList.remove('bg-emerald-600', 'text-white', 'shadow-lg');
                encodeBtn.classList.add('text-gray-400');
            }
        }
        
        // Auto-switch to decode tab if result exists
        {% if result_text %}
            switchTab('decode');
        {% endif %}
    </script>
</body>
</html>
"""

# ==========================================
#  FLASK ROUTES
# ==========================================


@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)


@app.route("/encode", methods=["POST"])
def encode_route():
    if "image" not in request.files or "text" not in request.form:
        flash("Missing image or text.", "error")
        return redirsect(url_for("home"))

    file = request.files["image"]
    text = request.form["text"]
    password = request.form.get("password", "")

    if file.filename == "":
        flash("No selected file.", "error")
        return redirect(url_for("home"))

    try:
        # Process the image
        output_stream = SteganographyEngine.encode(file, text, password)
        output_stream.seek(0)

        return send_file(
            output_stream,
            mimetype="image/png",
            as_attachment=True,
            download_name="encoded_image.png",
        )
    except Exception as e:
        flash(f"Encoding Error: {str(e)}", "error")
        return redirect(url_for("home"))


@app.route("/decode", methods=["POST"])
def decode_route():
    if "image" not in request.files:
        flash("Please upload an image.", "error")
        return redirect(url_for("home"))

    file = request.files["image"]
    password = request.form.get("password", "")

    try:
        decrypted_text = SteganographyEngine.decode(file, password)
        return render_template_string(HTML_TEMPLATE, result_text=decrypted_text)
    except Exception as e:
        flash(f"Decoding Error: {str(e)}", "error")
        return render_template_string(HTML_TEMPLATE)


if __name__ == "__main__":
    # Run on all interfaces for easy testing
    app.run(host="0.0.0.0", port=5000)
