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
# Wersja v11 - zawiera wszystkie poprawki
conn = sqlite3.connect('projekt_szkolny_v11.db', check_same_thread=False)
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

    # Inicjalizacja sesji
    if 'logged_in' not in st.session_state:
        st.session_state.update({
            'logged_in': False, 'user': '', 'role': '', 
            'temp_user': None, 'recovery_mode': False,
            'delete_step': 0
        })

    current_ip = get_remote_ip()

    # --- AUTO-LOGOWANIE PO ODŚWIEŻENIU ---
    if not st.session_state.logged_in and "session" in st.query_params:
        token = st.query_params["session"]
        c.execute('SELECT username FROM sessions WHERE session_token = ? AND ip_address = ?', (token, current_ip))
        res = c.fetchone()
        if res:
            c.execute('SELECT role FROM users WHERE username = ?', (res[0],))
            role_info = c.fetchone()
            if role_info:
                st.session_state.update({'logged_in': True, 'user': res[0], 'role': role_info[0]})

    # --- NAWIGACJA BOCZNA ---
    st.sidebar.title("🚀 SP2PC216 Mobile")
    
    menu_options = ["🏠 Start", "📥 Pobierz APK"]
    if not st.session_state.logged_in:
        menu_options += ["🔑 Logowanie", "📝 Rejestracja"]
    else:
        menu_options += ["🎧 Pomoc", "🛡️ Panel Zarządzania", "⚙️ Ustawienia"]
        if st.session_state.role == "Właściciel":
            menu_options.append("📁 Publikuj APK")

    choice = st.sidebar.radio("Nawigacja", menu_options)

    # --- OBSŁUGA SEKCE ---

    # 1. POBIERANIE APK (Publiczne)
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

    # 2. REJESTRACJA (Pełna logika)
    elif choice == "📝 Rejestracja":
        st.header("📝 Stwórz nowe konto")
        new_u = st.text_input("Login")
        new_p = st.text_input("Hasło", type="password")
        token = st.text_input("Token Rangi")

        if token == "SP24D.aternos.me.2015": # WŁAŚCICIEL
            st.warning("⚠️ Tryb Właściciela: Skonfiguruj 2FA i zapisz kody!")
            if 'reg_otp' not in st.session_state:
                st.session_state.reg_otp = pyotp.random_base32()
                st.session_state.reg_rec = generate_recovery_codes()
            
            totp = pyotp.TOTP(st.session_state.reg_otp)
            qr = qrcode.make(totp.provisioning_uri(name=new_u if new_u else "Owner", issuer_name="SP2PC216"))
            buf = BytesIO(); qr.save(buf, format="PNG")
            st.image(buf.getvalue(), caption="Zeskanuj w aplikacji Google Authenticator")
            
            st.info("🔑 KODY RATUNKOWE (Zapisz je teraz!):")
            st.write(", ".join([f"`{c}`" for c in st.session_state.reg_rec]))
            
            v_code = st.text_input("Wpisz kod z aplikacji telefonu")
            if st.button("Sfinalizuj rejestrację Właściciela"):
                if totp.verify(v_code):
                    try:
                        add_user(new_u, new_p, "Właściciel", st.session_state.reg_otp, st.session_state.reg_rec)
                        st.success("Konto Właściciela utworzone! Możesz się zalogować.")
                    except: st.error("Ten login jest już zajęty.")
                else: st.error("Kod 2FA jest nieprawidłowy.")

        else: # Standard / Admin
            if st.button("Zarejestruj konto"):
                role = ""
                if token == "SP2PC216Project:DP": role = "Standard"
                elif token == "JBSWY3DPEHPK3PXP": role = "Administrator"
                
                if role:
                    try:
                        add_user(new_u, new_p, role)
                        st.success(f"Zarejestrowano pomyślnie jako {role}!")
                    except: st.error("Login zajęty.")
                else: st.error("Nieprawidłowy token rangi.")

    # 3. LOGOWANIE (Pełna logika)
    elif choice == "🔑 Logowanie":
        if st.session_state.temp_user:
            st.header("🔐 Weryfikacja 2FA")
            otp = st.text_input("Kod z telefonu", max_chars=6)
            if st.button("Zatwierdź kod"):
                totp = pyotp.TOTP(st.session_state.temp_user['secret'])
                if totp.verify(otp):
                    u, r = st.session_state.temp_user['user'], st.session_state.temp_user['role']
                    new_t = str(uuid.uuid4())
                    c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, u, current_ip))
                    conn.commit()
                    st.session_state.update({'logged_in': True, 'user': u, 'role': r, 'temp_user': None})
                    st.query_params["session"] = new_t
                    st.rerun()
                else: st.error("Zły kod.")
        else:
            u_log = st.text_input("Login")
            p_log = st.text_input("Hasło", type="password")
            if st.button("Zaloguj się"):
                c.execute('SELECT password_hash, role, otp_secret FROM users WHERE username = ?', (u_log,))
                data = c.fetchone()
                if data and pbkdf2_sha256.verify(p_log, data[0]):
                    if data[2]: # Ma 2FA
                        st.session_state.temp_user = {'user': u_log, 'role': data[1], 'secret': data[2]}
                        st.rerun()
                    else:
                        new_t = str(uuid.uuid4())
                        c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, u_log, current_ip))
                        conn.commit()
                        st.session_state.update({'logged_in': True, 'user': u_log, 'role': data[1]})
                        st.query_params["session"] = new_t
                        st.rerun()
                else: st.error("Błędne dane logowania.")

    # 4. PUBLIKUJ APK (Właściciel)
    elif choice == "📁 Publikuj APK" and st.session_state.role == "Właściciel":
        st.title("📁 Publikacja nowej aplikacji APK")
        with st.form("upload_form", clear_on_submit=True):
            app_t = st.text_input("Nazwa aplikacji")
            app_d = st.text_area("Opis aplikacji / Co nowego?")
            app_f = st.file_uploader("Wybierz plik .apk", type=["apk"])
            if st.form_submit_button("Opublikuj na serwerze"):
                if app_t and app_f:
                    c.execute('INSERT INTO files (title, description, filename, file_data, upload_date) VALUES (?,?,?,?,?)',
                              (app_t, app_d, app_f.name, app_f.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M")))
                    conn.commit()
                    st.success("Aplikacja została dodana do listy pobierania!")
                else: st.error("Wypełnij nazwę i dodaj plik!")

    # 5. USTAWIENIA (W tym usuwanie konta)
    elif choice == "⚙️ Ustawienia":
        st.title("⚙️ Ustawienia Profilu")
        if st.button("WYLOGUJ"):
            c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
            conn.commit(); st.session_state.clear(); st.query_params.clear(); st.rerun()

        st.divider()
        st.subheader("❌ Usuwanie Konta")
        
        if st.session_state.delete_step == 0:
            if st.button("Rozpocznij procedurę usuwania konta"):
                st.session_state.delete_step = 1
                st.rerun()
        elif st.session_state.delete_step == 1:
            st.warning("⚠️ CZY NA PEWNO? To usunie wszystkie Twoje dane.")
            if st.button("TAK - przejdź do ostatniego kroku"):
                st.session_state.delete_step = 2
                st.rerun()
            if st.button("Anuluj"):
                st.session_state.delete_step = 0
                st.rerun()
        elif st.session_state.delete_step == 2:
            st.error("🛑 OSTATNIE OSTRZEŻENIE: Kliknięcie przycisku poniżej trwale skasuje konto.")
            if st.button("🔥 POTWIERDZAM DEFINITYWNIE - USUŃ", type="primary"):
                c.execute('DELETE FROM users WHERE username=?', (st.session_state.user,))
                c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
                conn.commit()
                st.session_state.clear(); st.query_params.clear(); st.rerun()
            if st.button("Wróć"):
                st.session_state.delete_step = 0
                st.rerun()

    # 6. PANEL ZARZĄDZANIA
    elif choice == "🛡️ Panel Zarządzania":
        st.title("🛡️ Panel Administracyjny")
        if st.session_state.role in ["Administrator", "Właściciel"]:
            users = list(c.execute('SELECT username, role, join_date, password_plain FROM users').fetchall())
            df = pd.DataFrame(users if st.session_state.role == "Właściciel" else [x[:3] for x in users],
                              columns=['User', 'Role', 'Joined', 'PlainPass'] if st.session_state.role == "Właściciel" else ['User', 'Role', 'Joined'])
            st.dataframe(df, use_container_width=True)
        else: st.error("Brak uprawnień.")

    elif choice == "🏠 Start":
        st.title("🏠 System SP2PC216")
        st.info("Witaj w panelu głównym.")

if __name__ == '__main__':
    main()
