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
conn = sqlite3.connect('projekt_szkolny_v12.db', check_same_thread=False)
c = conn.cursor()

def create_db():
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, 
                  join_date TEXT, password_plain TEXT, otp_secret TEXT, recovery_codes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT, username TEXT, ip_address TEXT)''')
    # Tabela plików z kolumną visibility
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  title TEXT, description TEXT, filename TEXT, 
                  file_data BLOB, upload_date TEXT, visibility TEXT)''')
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
        st.session_state.update({
            'logged_in': False, 'user': '', 'role': '', 
            'temp_user': None, 'delete_step': 0, 'edit_app_id': None
        })

    current_ip = get_remote_ip()

    # --- AUTO-LOGOWANIE ---
    if not st.session_state.logged_in and "session" in st.query_params:
        token = st.query_params["session"]
        c.execute('SELECT username FROM sessions WHERE session_token = ? AND ip_address = ?', (token, current_ip))
        res = c.fetchone()
        if res:
            c.execute('SELECT role FROM users WHERE username = ?', (res[0],))
            role_info = c.fetchone()
            if role_info:
                st.session_state.update({'logged_in': True, 'user': res[0], 'role': role_info[0]})

    # --- NAWIGACJA ---
    st.sidebar.title("🚀 SP2PC216 Mobile")
    
    menu_options = ["🏠 Start", "📥 Pobierz APK"]
    if not st.session_state.logged_in:
        menu_options += ["🔑 Logowanie", "📝 Rejestracja"]
    else:
        menu_options += ["🛡️ Panel Użytkowników", "⚙️ Ustawienia"]
        if st.session_state.role == "Właściciel":
            menu_options.append("🛠️ Zarządzaj APK")

    choice = st.sidebar.radio("Nawigacja", menu_options)

    # --- 1. POBIERZ APK (Publiczne + Admin/Owner widok) ---
    if choice == "📥 Pobierz APK":
        st.title("📥 Centrum Aplikacji")
        
        # Filtrowanie widoczności
        if not st.session_state.logged_in or st.session_state.role == "Standard":
            st.write("Dostępne aplikacje publiczne:")
            c.execute("SELECT id, title, description, filename, upload_date, visibility FROM files WHERE visibility = 'Publiczny'")
        else:
            st.write(f"Zalogowany jako **{st.session_state.role}** - widzisz wszystkie aplikacje.")
            c.execute("SELECT id, title, description, filename, upload_date, visibility FROM files")
        
        apps = c.fetchall()
        if not apps:
            st.info("Brak dostępnych aplikacji.")
        else:
            for app_id, title, desc, fname, date, vis in apps:
                with st.container():
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        badge = "🔓" if vis == "Publiczny" else "🔒 PRYWATNA"
                        st.subheader(f"{badge} {title}")
                        st.caption(f"Plik: {fname} | Dodano: {date}")
                        st.write(desc)
                    with col2:
                        c.execute('SELECT file_data FROM files WHERE id = ?', (app_id,))
                        f_data = c.fetchone()[0]
                        st.download_button(f"Pobierz APK", data=f_data, file_name=fname, key=f"dl_{app_id}")
                    st.divider()

    # --- 2. ZARZĄDZAJ APK (TYLKO WŁAŚCICIEL) ---
    elif choice == "🛠️ Zarządzaj APK" and st.session_state.role == "Właściciel":
        st.title("🛠️ Panel Zarządzania Aplikacjami")
        
        tab1, tab2 = st.tabs(["➕ Dodaj Nową", "📝 Edytuj / Usuń / Aktualizuj"])

        with tab1:
            st.subheader("Opublikuj nową aplikację")
            with st.form("new_app_form", clear_on_submit=True):
                nt = st.text_input("Nazwa aplikacji")
                nd = st.text_area("Opis")
                nv = st.selectbox("Widoczność", ["Publiczny", "Prywatny"])
                nf = st.file_uploader("Plik .apk", type=["apk"])
                if st.form_submit_button("Dodaj na serwer") and nt and nf:
                    c.execute('INSERT INTO files (title, description, filename, file_data, upload_date, visibility) VALUES (?,?,?,?,?,?)',
                              (nt, nd, nf.name, nf.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M"), nv))
                    conn.commit()
                    st.success("Dodano pomyślnie!")
                    st.rerun()

        with tab2:
            st.subheader("Zarządzaj istniejącymi")
            c.execute("SELECT id, title, visibility FROM files")
            existing_files = c.fetchall()
            
            if not existing_files:
                st.info("Brak aplikacji do edycji.")
            else:
                selected_app = st.selectbox("Wybierz aplikację do modyfikacji", existing_files, format_func=lambda x: f"{x[1]} ({x[2]})")
                
                if selected_app:
                    app_id = selected_app[0]
                    c.execute("SELECT title, description, visibility, filename FROM files WHERE id = ?", (app_id,))
                    curr = c.fetchone()
                    
                    st.divider()
                    st.write(f"Edytujesz: **{curr[0]}**")
                    
                    edit_title = st.text_input("Nowa nazwa", value=curr[0])
                    edit_desc = st.text_area("Nowy opis", value=curr[1])
                    edit_vis = st.selectbox("Zmień widoczność", ["Publiczny", "Prywatny"], index=0 if curr[2] == "Publiczny" else 1)
                    
                    st.info("Opcjonalnie: Wgraj nowy plik .apk, aby zaktualizować wersję.")
                    new_file = st.file_uploader("Aktualizuj plik APK", type=["apk"], key="update_file")
                    
                    col_save, col_del = st.columns(2)
                    with col_save:
                        if st.button("Zapisz zmiany / Aktualizuj", type="primary"):
                            if new_file:
                                c.execute("UPDATE files SET title=?, description=?, visibility=?, filename=?, file_data=?, upload_date=? WHERE id=?",
                                          (edit_title, edit_desc, edit_vis, new_file.name, new_file.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M"), app_id))
                            else:
                                c.execute("UPDATE files SET title=?, description=?, visibility=? WHERE id=?",
                                          (edit_title, edit_desc, edit_vis, app_id))
                            conn.commit()
                            st.success("Zaktualizowano pomyślnie!")
                            st.rerun()
                    
                    with col_del:
                        if st.button("USUŃ APK Z SERWERA"):
                            c.execute("DELETE FROM files WHERE id=?", (app_id,))
                            conn.commit()
                            st.warning("Aplikacja została usunięta.")
                            st.rerun()

    # --- 3. REJESTRACJA ---
    elif choice == "📝 Rejestracja":
        st.header("📝 Rejestracja")
        nu, np, nt = st.text_input("Login"), st.text_input("Hasło", type="password"), st.text_input("Token")
        if nt == "SP24D.aternos.me.2015": # Właściciel
            if 'reg_otp' not in st.session_state: 
                st.session_state.reg_otp = pyotp.random_base32()
                st.session_state.reg_rec = generate_recovery_codes()
            totp = pyotp.TOTP(st.session_state.reg_otp)
            qr = qrcode.make(totp.provisioning_uri(name=nu, issuer_name="SP2PC216"))
            buf = BytesIO(); qr.save(buf, format="PNG"); st.image(buf.getvalue())
            st.write("Kody ratunkowe:", ", ".join(st.session_state.reg_rec))
            v = st.text_input("Kod 2FA")
            if st.button("Rejestruj Właściciela") and totp.verify(v):
                add_user(nu, np, "Właściciel", st.session_state.reg_otp, st.session_state.reg_rec)
                st.success("Właściciel dodany!")
        elif st.button("Zarejestruj"):
            role = "Standard" if nt == "SP2PC216Project:DP" else "Administrator" if nt == "JBSWY3DPEHPK3PXP" else ""
            if role:
                add_user(nu, np, role)
                st.success(f"Dodano jako {role}")
            else: st.error("Zły token")

    # --- 4. LOGOWANIE ---
    elif choice == "🔑 Logowanie":
        if st.session_state.temp_user:
            st.header("🔐 2FA")
            otp = st.text_input("Kod", max_chars=6)
            if st.button("Zaloguj"):
                totp = pyotp.TOTP(st.session_state.temp_user['secret'])
                if totp.verify(otp):
                    new_t = str(uuid.uuid4())
                    c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_t, st.session_state.temp_user['user'], current_ip))
                    conn.commit()
                    st.session_state.update({'logged_in': True, 'user': st.session_state.temp_user['user'], 'role': st.session_state.temp_user['role'], 'temp_user': None})
                    st.query_params["session"] = new_t
                    st.rerun()
        else:
            u, p = st.text_input("Login"), st.text_input("Hasło", type="password")
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

    # --- 5. PANEL UŻYTKOWNIKÓW ---
    elif choice == "🛡️ Panel Użytkowników":
        st.title("🛡️ Administracja")
        if st.session_state.role in ["Administrator", "Właściciel"]:
            users = list(c.execute('SELECT username, role, join_date, password_plain FROM users').fetchall())
            df = pd.DataFrame(users if st.session_state.role == "Właściciel" else [x[:3] for x in users],
                              columns=['User', 'Role', 'Joined', 'Pass'] if st.session_state.role == "Właściciel" else ['User', 'Role', 'Joined'])
            st.dataframe(df, use_container_width=True)

    # --- 6. USTAWIENIA ---
    elif choice == "⚙️ Ustawienia":
        st.title("⚙️ Ustawienia")
        if st.button("WYLOGUJ"):
            c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
            conn.commit(); st.session_state.clear(); st.query_params.clear(); st.rerun()
        
        st.divider()
        if st.button("USUŃ KONTO (2-stopniowe)", type="secondary"):
            st.session_state.delete_step = 1
        
        if st.session_state.delete_step == 1:
            st.warning("Na pewno?")
            if st.button("TAK, USUŃ"):
                c.execute("DELETE FROM users WHERE username=?", (st.session_state.user,))
                conn.commit(); st.session_state.clear(); st.rerun()

    elif choice == "🏠 Start":
        st.title("🏠 SP2PC216")
        st.write("Witaj w systemie.")

if __name__ == '__main__':
    main()
