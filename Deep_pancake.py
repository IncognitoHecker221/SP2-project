import streamlit as st
import sqlite3
import uuid
import urllib.request
import pyotp
import qrcode
import random
import string
from io import BytesIO
from passlib.hash import pbkdf2_sha256
from datetime import datetime
import pandas as pd

# --- FUNKCJE POMOCNICZE ---
def get_remote_ip():
    try:
        return urllib.request.urlopen('https://ident.me').read().decode('utf8')
    except:
        return "127.0.0.1"

def generate_recovery_codes(n=5):
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=10)) for _ in range(n)]

# --- BAZA DANYCH ---
conn = sqlite3.connect('projekt_szkolny_v10.db', check_same_thread=False)
c = conn.cursor()

def create_db():
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, 
                  join_date TEXT, password_plain TEXT, otp_secret TEXT, recovery_codes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS warnings
                 (target_user TEXT, sender TEXT, reason TEXT, date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT, username TEXT, ip_address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  title TEXT, description TEXT, filename TEXT, 
                  file_data BLOB, upload_date TEXT)''')
    conn.commit()

def add_user(username, password, role, otp_secret=None, recovery_codes=None):
    hashed = pbkdf2_sha256.hash(password)
    codes_str = ",".join(recovery_codes) if recovery_codes else None
    c.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',
              (username, hashed, role, datetime.now().strftime("%Y-%m-%d %H:%M"), password, otp_secret, codes_str))
    conn.commit()

# --- GŁÓWNA LOGIKA ---
def main():
    st.set_page_config(page_title="System SP2PC216", layout="wide", page_icon="🔐")
    create_db()

    # Inicjalizacja stanów sesji
    if 'logged_in' not in st.session_state:
        st.session_state.update({
            'logged_in': False, 'user': '', 'role': '', 
            'temp_user': None, 'recovery_mode': False,
            'delete_step': 0  # Stan dla usuwania konta
        })

    current_ip = get_remote_ip()

    # --- AUTO-LOGOWANIE ---
    if not st.session_state.logged_in and "session" in st.query_params:
        token = st.query_params["session"]
        c.execute('SELECT username FROM sessions WHERE session_token = ? AND ip_address = ?', (token, current_ip))
        res = c.fetchone()
        if res:
            c.execute('SELECT role FROM users WHERE username = ?', (res[0],))
            st.session_state.update({'logged_in': True, 'user': res[0], 'role': c.fetchone()[0]})

    # --- MENU BOCZNE ---
    st.sidebar.title("🚀 SP2PC216 Mobile")
    
    menu_options = ["🏠 Start", "📥 Pobierz APK"]
    if not st.session_state.logged_in:
        menu_options += ["🔑 Logowanie", "📝 Rejestracja"]
    else:
        menu_options += ["🎧 Pomoc", "⚙️ Ustawienia", "🛡️ Panel Zarządzania"]
        if st.session_state.role == "Właściciel":
            menu_options.append("📁 Publikuj APK")

    choice = st.sidebar.radio("Nawigacja", menu_options)

    # --- SEKCJE ---

    if choice == "📥 Pobierz APK":
        st.title("📥 Pobierz nasze aplikacje (.apk)")
        c.execute('SELECT id, title, description, filename, upload_date FROM files')
        apps = c.fetchall()
        if not apps:
            st.info("Brak dostępnych aplikacji.")
        else:
            for app_id, title, desc, fname, date in apps:
                with st.container():
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.subheader(f"📱 {title}")
                        st.caption(f"Plik: {fname} | Dodano: {date}")
                        st.write(desc)
                    with col2:
                        c.execute('SELECT file_data FROM files WHERE id = ?', (app_id,))
                        f_data = c.fetchone()[0]
                        st.download_button("Pobierz APK", data=f_data, file_name=fname, key=f"dl_{app_id}")
                    st.divider()

    elif choice == "📁 Publikuj APK" and st.session_state.role == "Właściciel":
        st.title("📁 Publikacja nowej aplikacji")
        with st.form("upload_form"):
            app_title = st.text_input("Tytuł aplikacji")
            app_desc = st.text_area("Opis aplikacji")
            uploaded_file = st.file_uploader("Wybierz plik", type=["apk"])
            if st.form_submit_button("Opublikuj") and app_title and uploaded_file:
                c.execute('INSERT INTO files (title, description, filename, file_data, upload_date) VALUES (?,?,?,?,?)',
                          (app_title, app_desc, uploaded_file.name, uploaded_file.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M")))
                conn.commit()
                st.success("Opublikowano!")

    elif choice == "⚙️ Ustawienia" and st.session_state.logged_in:
        st.title("⚙️ Ustawienia Konta")
        
        # Sekcja Wylogowania
        if st.button("WYLOGUJ MNIE"):
            c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
            conn.commit()
            st.session_state.clear()
            st.query_params.clear()
            st.rerun()

        st.divider()
        
        # --- SEKCJA USUWANIA KONTA (2 POTWIERDZENIA) ---
        st.subheader("❌ Usuwanie Konta")
        
        if st.session_state.delete_step == 0:
            if st.button("Chcę usunąć swoje konto"):
                st.session_state.delete_step = 1
                st.rerun()

        elif st.session_state.delete_step == 1:
            st.warning("⚠️ KROK 1: Czy na pewno chcesz usunąć konto? Wszystkie dane zostaną skasowane.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("TAK, przejdź dalej"):
                    st.session_state.delete_step = 2
                    st.rerun()
            with col2:
                if st.button("Anuluj"):
                    st.session_state.delete_step = 0
                    st.rerun()

        elif st.session_state.delete_step == 2:
            st.error("🛑 KROK 2 (OSTATNI): To działanie jest nieodwracalne. Kliknij poniżej, aby trwale usunąć konto.")
            if st.button("🔥 POTWIERDZAM DEFINITYWNIE - USUŃ KONTO", type="primary"):
                c.execute('DELETE FROM users WHERE username=?', (st.session_state.user,))
                c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
                conn.commit()
                st.session_state.clear()
                st.query_params.clear()
                st.rerun()
            if st.button("Wróć"):
                st.session_state.delete_step = 0
                st.rerun()

    # Logika logowania i rejestracji (identyczna jak wcześniej)
    elif choice == "🔑 Logowanie":
        # ... (kod logowania z 2FA) ...
        u = st.text_input("Użytkownik")
        p = st.text_input("Hasło", type="password")
        if st.button("Zaloguj"):
            c.execute('SELECT password_hash, role, otp_secret FROM users WHERE username = ?', (u,))
            data = c.fetchone()
            if data and pbkdf2_sha256.verify(p, data[0]):
                new_t = str(uuid.uuid4())
                c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, u, current_ip))
                conn.commit()
                st.session_state.update({'logged_in': True, 'user': u, 'role': data[1]})
                st.query_params["session"] = new_t
                st.rerun()

    elif choice == "🏠 Start":
        st.title("🏠 Oficjalny System SP2PC216")
        st.write("Użytkownik: **" + (st.session_state.user if st.session_state.user else "Niezalogowany") + "**")

if __name__ == '__main__':
    main()
