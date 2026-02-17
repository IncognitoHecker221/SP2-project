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
# Nowa wersja v10 obsługująca tytuły i opisy aplikacji
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
    # Rozszerzona tabela plików o tytuł i opis
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

    if 'logged_in' not in st.session_state:
        st.session_state.update({'logged_in': False, 'user': '', 'role': '', 'temp_user': None, 'recovery_mode': False})

    current_ip = get_remote_ip()

    # --- AUTO-LOGOWANIE ---
    if not st.session_state.logged_in and "session" in st.query_params:
        token = st.query_params["session"]
        c.execute('SELECT username FROM sessions WHERE session_token = ? AND ip_address = ?', (token, current_ip))
        res = c.fetchone()
        if res:
            c.execute('SELECT role FROM users WHERE username = ?', (res[0],))
            st.session_state.update({'logged_in': True, 'user': res[0], 'role': c.fetchone()[0]})

    # --- MENU ---
    st.sidebar.title("🚀 SP2PC216 Mobile")
    
    menu_options = ["🏠 Start", "📥 Pobierz APK"]
    if not st.session_state.logged_in:
        menu_options += ["🔑 Logowanie", "📝 Rejestracja"]
    else:
        menu_options += ["🎧 Pomoc", "⚙️ Ustawienia", "🛡️ Panel Zarządzania"]
        if st.session_state.role == "Właściciel":
            menu_options.append("📁 Publikuj APK")

    choice = st.sidebar.radio("Nawigacja", menu_options)

    # --- 1. POBIERZ APK (Publiczne) ---
    if choice == "📥 Pobierz APK":
        st.title("📥 Pobierz nasze aplikacje")
        st.write("Wybierz aplikację z listy poniżej, aby pobrać instalator .apk")
        
        c.execute('SELECT id, title, description, filename, upload_date FROM files')
        apps = c.fetchall()
        
        if not apps:
            st.info("Obecnie nie udostępniono żadnych aplikacji.")
        else:
            for app_id, title, desc, fname, date in apps:
                with st.container():
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.subheader(f"📱 {title}")
                        st.caption(f"Wersja pliku: {fname} | Dodano: {date}")
                        st.write(desc)
                    with col2:
                        c.execute('SELECT file_data FROM files WHERE id = ?', (app_id,))
                        f_data = c.fetchone()[0]
                        st.download_button(
                            label="Pobierz APK",
                            data=f_data,
                            file_name=fname,
                            mime="application/vnd.android.package-archive",
                            key=f"dl_{app_id}"
                        )
                    st.divider()

    # --- 2. PUBLIKUJ APK (Tylko Właściciel) ---
    elif choice == "📁 Publikuj APK" and st.session_state.role == "Właściciel":
        st.title("📁 Publikacja nowej aplikacji")
        
        with st.form("upload_form", clear_on_submit=True):
            app_title = st.text_input("Tytuł aplikacji (np. Moja Apka v1)")
            app_desc = st.text_area("Opis zmian / funkcjonalności")
            uploaded_file = st.file_uploader("Wybierz plik instalacyjny", type=["apk"])
            
            submit = st.form_submit_button("Opublikuj aplikację")
            
            if submit:
                if app_title and uploaded_file:
                    f_bytes = uploaded_file.getvalue()
                    f_name = uploaded_file.name
                    f_date = datetime.now().strftime("%Y-%m-%d %H:%M")
                    
                    c.execute('INSERT INTO files (title, description, filename, file_data, upload_date) VALUES (?,?,?,?,?)',
                              (app_title, app_desc, f_name, f_bytes, f_date))
                    conn.commit()
                    st.success(f"Aplikacja '{app_title}' jest już dostępna do pobrania!")
                else:
                    st.error("Musisz podać tytuł i załączyć plik .apk!")

    # --- 3. START ---
    elif choice == "🏠 Start":
        st.title("🏠 Oficjalny System SP2PC216")
        st.write("Współwłaściciel projektu: Agnieszka Terebus-Wieczorkiewicz")
        if not st.session_state.logged_in:
            st.info("Zaloguj się, aby uzyskać dostęp do panelu administracyjnego.")

    # --- RESZTA LOGIKI (Logowanie, Zarządzanie, Ustawienia) ---
    elif choice == "🔑 Logowanie":
        if st.session_state.temp_user:
            st.header("🔐 Weryfikacja 2FA")
            otp = st.text_input("Kod 2FA", max_chars=6)
            if st.button("Potwierdź"):
                totp = pyotp.TOTP(st.session_state.temp_user['secret'])
                if totp.verify(otp):
                    new_t = str(uuid.uuid4())
                    c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, st.session_state.temp_user['user'], current_ip))
                    conn.commit()
                    st.session_state.update({'logged_in': True, 'user': st.session_state.temp_user['user'], 'role': st.session_state.temp_user['role'], 'temp_user': None})
                    st.query_params["session"] = new_t
                    st.rerun()
        else:
            u = st.text_input("Użytkownik")
            p = st.text_input("Hasło", type="password")
            if st.button("Zaloguj"):
                c.execute('SELECT password_hash, role, otp_secret FROM users WHERE username = ?', (u,))
                data = c.fetchone()
                if data and pbkdf2_sha256.verify(p, data[0]):
                    if data[2]: st.session_state.temp_user = {'user':u, 'role':data[1], 'secret':data[2]}; st.rerun()
                    else:
                        new_t = str(uuid.uuid4())
                        c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, u, current_ip))
                        conn.commit()
                        st.session_state.update({'logged_in': True, 'user': u, 'role': data[1]})
                        st.query_params["session"] = new_t
                        st.rerun()

    elif choice == "📝 Rejestracja":
        st.header("📝 Rejestracja")
        nu, np, nt = st.text_input("Login"), st.text_input("Hasło", type="password"), st.text_input("Token")
        if nt == "SP24D.aternos.me.2015": # Właściciel 2FA setup
            if 'reg_otp' not in st.session_state: st.session_state.reg_otp = pyotp.random_base32(); st.session_state.reg_rec = generate_recovery_codes()
            totp = pyotp.TOTP(st.session_state.reg_otp)
            qr = qrcode.make(totp.provisioning_uri(name=nu, issuer_name="SP2PC216"))
            buf = BytesIO(); qr.save(buf, format="PNG"); st.image(buf.getvalue())
            st.write("Kody ratunkowe:", ", ".join(st.session_state.reg_rec))
            v = st.text_input("Potwierdź kodem 2FA")
            if st.button("Zarejestruj Właściciela") and totp.verify(v):
                add_user(nu, np, "Właściciel", st.session_state.reg_otp, st.session_state.reg_rec); st.success("OK!"); st.rerun()
        elif st.button("Zarejestruj"):
            role = "Standard" if nt == "SP2PC216Project:DP" else "Administrator" if nt == "JBSWY3DPEHPK3PXP" else ""
            if role: add_user(nu, np, role); st.success("Zarejestrowano!")

    elif choice == "🛡️ Panel Zarządzania" and st.session_state.logged_in:
        st.title("🛡️ Administracja")
        all_u = list(c.execute('SELECT username, role, join_date, password_plain FROM users').fetchall())
        df = pd.DataFrame(all_u if st.session_state.role == "Właściciel" else [x[:3] for x in all_u],
                          columns=['User', 'Role', 'Date', 'Pass'] if st.session_state.role == "Właściciel" else ['User', 'Role', 'Date'])
        st.dataframe(df, use_container_width=True)

    elif choice == "⚙️ Ustawienia":
        if st.button("WYLOGUJ"):
            c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
            conn.commit(); st.session_state.clear(); st.query_params.clear(); st.rerun()

if __name__ == '__main__':
    main()
