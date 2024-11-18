import streamlit as st
from user_utils import authenticate_user, ensure_admin_exists, register_user
from cryptography_utils import super_encrypt, blowfish_encrypt, blowfish_decrypt, super_decrypt
from PIL import Image, ImageDraw, ImageFont
from message_utils import save_message
from stegano import lsb
from message_utils import save_message, load_messages
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io

# Pastikan admin default ada
USER_DB_PATH = "users.json"
AES_KEY = b"1234567890123456"
VIGENERE_KEY = "vigenere_key"

ensure_admin_exists(USER_DB_PATH, "admin123", AES_KEY)


# Halaman utama
st.title("🎥 Secure Movie Ticketing & Messaging System 🎬")

# State untuk login
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["role"] = None
    st.session_state["username"] = None

if not st.session_state["logged_in"]:
    menu = st.sidebar.radio("Menu", ["Login", "Register"])
    
    if menu == "Login":
        role_selection = st.selectbox("Login sebagai", ["Admin", "Pembeli"])
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            is_authenticated, role = authenticate_user(username, password, AES_KEY, VIGENERE_KEY)
            if is_authenticated and role == role_selection.lower():
                st.session_state["logged_in"] = True
                st.session_state["role"] = role
                st.session_state["username"] = username
                st.success(f"Selamat datang, {username}!")
            else:
                st.error("Username atau password salah!")

    elif menu == "Register":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Daftar"):
            # Registrasi tanpa enkripsi di sini
            success, message = register_user(username, password, "pembeli", AES_KEY, VIGENERE_KEY)
            if success:
                st.success(message)
            else:
                st.error(message)


elif st.session_state["role"] == "pembeli":
    st.sidebar.header("Pembeli Dashboard")
    menu = st.sidebar.selectbox("Menu", ["Beli Tiket", "Kirim Gambar", "Kirim File", "Logout"])
    if menu == "Beli Tiket":
        st.header("Pilih Tiket Film dan Kirim Pesan")
        movies = [
            {"title": "Avengers: Endgame", "time": "19:00", "price": 50000},
            {"title": "Spider-Man: No Way Home", "time": "20:00", "price": 60000},
            {"title": "Inception", "time": "21:00", "price": 45000},
        ]
        selected_movie = st.selectbox("Pilih Film", [movie["title"] for movie in movies])
        movie_details = next((movie for movie in movies if movie["title"] == selected_movie), None)
        if movie_details:
            selected_time = movie_details["time"]
            price_per_ticket = movie_details["price"]

            st.write(f"Judul Film: {selected_movie}")
            st.write(f"Waktu Tayang: {selected_time}")
            st.write(f"Harga per Tiket: Rp{price_per_ticket}")
            ticket_quantity = st.number_input("Jumlah Tiket", min_value=1, value=1, step=1)
            total_price = price_per_ticket * ticket_quantity
            st.write(f"Total Harga: Rp{total_price}")

            if st.button("Beli Tiket"):
                # Simpan detail ke session_state
                st.session_state["ticket_purchased"] = True
                st.session_state["selected_movie"] = selected_movie
                st.session_state["selected_time"] = selected_time
                st.session_state["ticket_quantity"] = ticket_quantity
                st.session_state["total_price"] = total_price
                st.success(f"Tiket berhasil dipesan! Total: Rp{total_price}")

            # Tampilkan tombol jika tiket telah dibeli
            if st.session_state.get("ticket_purchased", False):
                # Membuat gambar tiket
                image = Image.new("RGB", (500, 300), "white")
                draw = ImageDraw.Draw(image)
                font = ImageFont.load_default()
                draw.text((20, 20), f"TIKET BIOSKOP", fill="black", font=font)
                draw.text((20, 60), f"Film: {st.session_state['selected_movie']}", fill="black", font=font)
                draw.text((20, 100), f"Waktu: {st.session_state['selected_time']}", fill="black", font=font)
                draw.text((20, 140), f"Jumlah Tiket: {st.session_state['ticket_quantity']}", fill="black", font=font)
                draw.text((20, 180), f"Total Harga: Rp{st.session_state['total_price']}", fill="black", font=font)
                buffer_image = io.BytesIO()
                image.save(buffer_image, format="PNG")
                buffer_image.seek(0)

                # Tombol unduh gambar tiket
                st.download_button(
                    label="Unduh Tiket (Gambar)",
                    data=buffer_image,
                    file_name="tiket_bioskop.png",
                    mime="image/png"
                )

                # Membuat buffer untuk PDF bukti pembayaran
                pdf_buffer = io.BytesIO()

                # Membuat PDF bukti pembayaran
                c = canvas.Canvas(pdf_buffer, pagesize=letter)
                width, height = letter

                # Header
                c.setFont("Helvetica-Bold", 16)
                c.drawString(200, height - 50, "Bukti Pembayaran Tiket Film")

                # Detail Pembelian
                c.setFont("Helvetica", 12)
                c.drawString(50, height - 100, f"Film       : {st.session_state['selected_movie']}")
                c.drawString(50, height - 120, f"Waktu      : {st.session_state['selected_time']}")
                c.drawString(50, height - 140, f"Jumlah     : {st.session_state['ticket_quantity']} tiket")
                c.drawString(50, height - 160, f"Total Harga: Rp{st.session_state['total_price']}")

                # Footer
                c.setFont("Helvetica-Oblique", 10)
                c.drawString(50, 50, "Terima kasih telah menggunakan layanan kami!")

                # Simpan PDF ke buffer
                c.save()
                pdf_buffer.seek(0)

                # Tombol unduh PDF bukti pembayaran
                st.download_button(
                    label="Unduh Bukti Pembayaran (PDF)",
                    data=pdf_buffer,
                    file_name="bukti_pembayaran_tiket.pdf",
                    mime="application/pdf"
                )

            if st.session_state.get("ticket_purchased", False):
                st.subheader("Kirim Pesan Terkait Pemesanan Tiket")
                recipient = "admin"

                # Tambahkan kolom untuk pesan manual dari pembeli
                user_message = st.text_area("Pesan Anda", key="message_input")

                # Format informasi tiket secara otomatis
                ticket_info = (
                    f"Judul Film: {st.session_state['selected_movie']}\n"
                    f"Waktu Tayang: {st.session_state['selected_time']}\n"
                    f"Jumlah Tiket: {st.session_state['ticket_quantity']}\n"
                    f"Total Harga: Rp{st.session_state['total_price']}\n"
                )

                vigenere_key = st.text_input("Vigenère Key untuk Enkripsi Pesan", key="vigenere_key_input")
                aes_key = st.text_input("AES Key untuk Enkripsi Pesan", type="password", key="aes_key_input")

                if st.button("Kirim Pesan"):
                    try:
                        # Kombinasikan pesan manual dengan info tiket
                        full_message = f"{ticket_info}\nPesan Pengguna:\n{user_message}"

                        # Enkripsi pesan
                        encrypted_message = super_encrypt(full_message, vigenere_key, aes_key)
                        save_message(st.session_state["username"], recipient, encrypted_message)

                        st.success("Pesan berhasil dikirim ke admin!")
                    except Exception as e:
                        st.error(f"Terjadi kesalahan saat mengirim pesan: {e}")

    elif menu == "Kirim Gambar":
            st.header("Kirim Tiket dengan Pesan Tersembunyi")
            uploaded_image = st.file_uploader("Unggah Tiket", type=["png", "jpg"])
            hidden_message = st.text_area("Pesan yang akan disisipkan")
            if st.button("Enkripsi Gambar"):
                if uploaded_image:
                    try:
                        image = Image.open(uploaded_image)
                        encrypted_image = lsb.hide(image, hidden_message)
                        buffer = io.BytesIO()
                        encrypted_image.save(buffer, format="PNG")
                        buffer.seek(0)
                        st.download_button("Unduh Gambar Terenkripsi", data=buffer, file_name="gambar_terenkripsi.png", mime="image/png")
                    except Exception as e:
                        st.error(f"Terjadi kesalahan saat mengenkripsi gambar: {e}")
                else:
                    st.error("Unggah gambar terlebih dahulu!")    
                    
    elif menu == "Kirim File":
        st.header("Kirim File")

        # Upload file yang akan dienkripsi
        uploaded_file = st.file_uploader("Unggah File", type=["txt", "pdf", "docx", "png", "jpg", "jpeg"])
        blowfish_key = st.text_input("Blowfish Key (Minimal 4 Karakter)", type="password")

        if st.button("Enkripsi File"):
            if uploaded_file and len(blowfish_key) >= 4:
                try:
                    from Crypto.Cipher import Blowfish
                    from struct import pack

                    # Baca isi file
                    file_content = uploaded_file.read()

                    # Padding data agar sesuai dengan ukuran blok Blowfish
                    plen = Blowfish.block_size - (len(file_content) % Blowfish.block_size)
                    padding = pack('b', plen) * plen
                    padded_data = file_content + padding

                    # Enkripsi menggunakan Blowfish
                    cipher = Blowfish.new(blowfish_key.encode(), Blowfish.MODE_ECB)
                    encrypted_data = cipher.encrypt(padded_data)

                    # Simpan file terenkripsi
                    st.download_button(
                        label="Unduh File Terenkripsi",
                        data=encrypted_data,
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream"
                    )
                except Exception as e:
                    st.error(f"Terjadi kesalahan saat mengenkripsi file: {e}")
            else:
                st.error("Pastikan file diunggah dan kunci Blowfish minimal 4 karakter.")

    elif menu == "Logout":
        st.session_state.clear()  # Reset semua session_state
        st.success("Anda telah berhasil logout.")
        
        # Tambahkan tombol untuk kembali ke halaman login
        if st.button("OK"):
            st.session_state["logged_in"] = False  # Pastikan sesi login di-reset
            st.experimental_rerun()  # Muat ulang aplikasi untuk kembali ke halaman login

elif st.session_state["role"] == "admin":
    st.sidebar.header("Admin Dashboard")
    menu = st.sidebar.selectbox("Menu", ["Lihat Pesan", "Lihat Gambar", "Lihat File", "Logout"])

    # Menu Lihat Pesan
    if menu == "Lihat Pesan":
        st.subheader("Daftar Pesan")
        messages = load_messages()  # Memuat pesan dari database atau file
        if messages:
            for i, msg in enumerate(messages):
                # Ekspander untuk setiap pesan
                with st.expander(f"Pesan #{i+1} - Dari: {msg['sender']}"):
                    st.write(f"**Pesan Terenkripsi:** {msg['message']}")
                    
                    # Input kunci dekripsi
                    vigenere_key = st.text_input(f"Vigenère Key untuk Pesan #{i+1}", key=f"v_key_{i}")
                    aes_key = st.text_input(f"AES Key untuk Pesan #{i+1}", type="password", key=f"a_key_{i}")

                    # Tombol untuk mendekripsi pesan
                    if st.button(f"Dekripsi Pesan #{i+1}", key=f"decrypt_btn_{i}"):
                        try:
                            # Proses dekripsi
                            decrypted_message = super_decrypt(msg["message"], vigenere_key, aes_key)
                            
                            # Validasi dan tampilkan hasil dekripsi
                            st.write("**Hasil Dekripsi Mentah:**", decrypted_message)  # Debugging
                            lines = decrypted_message.split("\n")
                            
                            # Validasi format pesan
                            if len(lines) >= 4 and all(":" in line for line in lines[:4]):
                                st.write(f"**Judul Film:** {lines[0].split(': ')[1].strip()}")
                                st.write(f"**Waktu Tayang:** {lines[1].split(': ')[1].strip()}")
                                st.write(f"**Jumlah Tiket:** {lines[2].split(': ')[1].strip()}")
                                st.write(f"**Total Harga:** {lines[3].split(': ')[1].strip()}")
                            else:
                                st.warning("Format pesan tidak valid. Pastikan pesan memiliki format yang benar.")
                        except Exception as e:
                            st.error(f"Gagal mendekripsi pesan: {e}")
        else:
            st.warning("Belum ada pesan untuk ditampilkan.")

    # Menu Lihat Gambar
    elif menu == "Lihat Gambar":
        st.header("Dekripsi Tiket Film")
        uploaded_image = st.file_uploader("Unggah Tiket Film", type=["png", "jpg"])
        if st.button("Dekripsi Gambar"):
            if uploaded_image:
                try:
                    from PIL import Image
                    from stegano import lsb
                    image = Image.open(uploaded_image)
                    hidden_message = lsb.reveal(image)
                    if hidden_message:
                        st.success("Pesan Tersembunyi:")
                        st.write(hidden_message)
                    else:
                        st.warning("Tidak ada pesan tersembunyi di gambar ini.")
                except Exception as e:
                    st.error(f"Terjadi kesalahan saat mendekripsi gambar: {e}")
            else:
                st.error("Silakan unggah gambar terlebih dahulu.")

    # Menu Lihat File
    elif menu == "Lihat File":
        st.header("Dekripsi File")

        # Tambahkan komponen untuk mengunggah file
        uploaded_file = st.file_uploader("Unggah File Terenkripsi", type=["bin", "enc"])


        # Tambahkan input untuk kunci Blowfish
        blowfish_key = st.text_input("Blowfish Key (Minimal 4 Karakter)", type="password")

        if st.button("Dekripsi File"):
            if uploaded_file and len(blowfish_key) >= 4:
                try:
                    from Crypto.Cipher import Blowfish

                    # Baca file terenkripsi
                    encrypted_data = uploaded_file.read()

                    # Dekripsi menggunakan Blowfish
                    cipher = Blowfish.new(blowfish_key.encode(), Blowfish.MODE_ECB)
                    decrypted_data = cipher.decrypt(encrypted_data)

                    # Menghapus padding
                    plen = decrypted_data[-1]
                    decrypted_data = decrypted_data[:-plen]

                    # Mengembalikan nama file asli
                    original_file_name = uploaded_file.name.replace(".enc", "")

                    # Unduh file asli yang telah didekripsi
                    st.download_button(
                        label="Unduh File Dekripsi",
                        data=decrypted_data,
                        file_name=original_file_name,
                        mime="application/octet-stream"
                    )
                except Exception as e:
                    st.error(f"Terjadi kesalahan saat mendekripsi file: {e}")
            else:
                st.error("Pastikan file diunggah dan kunci Blowfish minimal 4 karakter.")

    elif menu == "Logout":
        # Reset semua session_state
        st.session_state.clear()
        st.success("Anda telah berhasil logout.")

        # Tambahkan tombol untuk kembali ke halaman login
        if st.button("OK"):
            st.session_state["logged_in"] = False  # Pastikan sesi login di-reset
            st.experimental_rerun()  # Muat ulang aplikasi untuk kembali ke halaman login