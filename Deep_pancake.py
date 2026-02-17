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
conn = sqlite3.connect('projekt_szkolny_v14.db', check_same_thread=False)
c = conn.cursor()

def create_db():
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, 
                  join_date TEXT, password_plain TEXT, otp_secret TEXT, recovery_codes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT, username TEXT, ip_address TEXT)''')
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
            'temp_user': None, 'delete_step': 0
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

    # --- 1. POBIERZ APK ---
    if choice == "📥 Pobierz APK":
        st.title("📥 Centrum Aplikacji")
        
        # Kogo co widzi:
        # Właściciel/Admin: Wszystko
        # Gość/Standard: Wszystko OPRÓCZ 'Prywatny'
        if st.session_state.logged_in and st.session_state.role in ["Właściciel", "Administrator"]:
            c.execute("SELECT id, title, description, filename, upload_date, visibility FROM files")
        else:
            c.execute("SELECT id, title, description, filename, upload_date, visibility FROM files WHERE visibility != 'Prywatny'")
        
        apps = c.fetchall()
        if not apps:
            st.info("Brak dostępnych aplikacji.")
        else:
            for app_id, title, desc, fname, date, vis in apps:
                with st.container():
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        # Dobór ikony do statusu
                        icons = {"Publiczny": "🔓", "Tylko zalogowani": "👤", "Tylko podgląd": "👁️", "Prywatny": "🔒"}
                        st.subheader(f"{icons.get(vis, '❓')} {title}")
                        st.caption(f"Widoczność: {vis} | Dodano: {date}")
                        st.write(desc)
                    with col2:
                        # Logika uprawnień do POBRANIA
                        can_download = False
                        msg = "Zablokowane"

                        if vis == "Publiczny":
                            can_download = True
                        elif vis == "Tylko zalogowani":
                            if st.session_state.logged_in:
                                can_download = True
                            else:
                                msg = "Zaloguj się, aby pobrać"
                        elif vis == "Tylko podgląd" or vis == "Prywatny":
                            if st.session_state.logged_in and st.session_state.role in ["Właściciel", "Administrator"]:
                                can_download = True
                            else:
                                msg = "Tylko dla administracji"

                        if can_download:
                            c.execute('SELECT file_data FROM files WHERE id = ?', (app_id,))
                            f_data = c.fetchone()[0]
                            st.download_button(f"Pobierz APK", data=f_data, file_name=fname, key=f"dl_{app_id}")
                        else:
                            st.warning(msg)
                    st.divider()

    # --- 2. ZARZĄDZAJ APK (TYLKO WŁAŚCICIEL) ---
    elif choice == "🛠️ Zarządzaj APK" and st.session_state.role == "Właściciel":
        st.title("🛠️ Zarządzanie plikami APK")
        tab1, tab2 = st.tabs(["➕ Nowa Aplikacja", "📝 Edycja i Aktualizacja"])

        with tab1:
            with st.form("add_form_v14", clear_on_submit=True):
                t = st.text_input("Nazwa aplikacji")
                d = st.text_area("Opis")
                v = st.selectbox("Widoczność", ["Publiczny", "Tylko zalogowani", "Tylko podgląd", "Prywatny"])
                f = st.file_uploader("Wybierz plik .apk", type=["apk"])
                if st.form_submit_button("Dodaj do bazy") and t and f:
                    c.execute('INSERT INTO files (title, description, filename, file_data, upload_date, visibility) VALUES (?,?,?,?,?,?)',
                              (t, d, f.name, f.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M"), v))
                    conn.commit()
                    st.success("Dodano aplikację!")
                    st.rerun()

        with tab2:
            c.execute("SELECT id, title, visibility FROM files")
            files_list = c.fetchall()
            if files_list:
                sel = st.selectbox("Wybierz aplikację", files_list, format_func=lambda x: f"{x[1]} ({x[2]})")
                if sel:
                    aid = sel[0]
                    c.execute("SELECT title, description, visibility FROM files WHERE id=?", (aid,))
                    curr = c.fetchone()
                    
                    et = st.text_input("Nazwa", value=curr[0])
                    ed = st.text_area("Opis", value=curr[1])
                    ev = st.selectbox("Widoczność", ["Publiczny", "Tylko zalogowani", "Tylko podgląd", "Prywatny"], 
                                      index=["Publiczny", "Tylko zalogowani", "Tylko podgląd", "Prywatny"].index(curr[2]))
                    
                    new_apk = st.file_uploader("Podmień plik APK (Aktualizacja)", type=["apk"])
                    
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("Zapisz zmiany"):
                            if new_apk:
                                c.execute("UPDATE files SET title=?, description=?, visibility=?, filename=?, file_data=?, upload_date=? WHERE id=?",
                                          (et, ed, ev, new_apk.name, new_apk.getvalue(), datetime.now().strftime("%Y-%m-%d %H:%M"), aid))
                            else:
                                c.execute("UPDATE files SET title=?, description=?, visibility=? WHERE id=?", (et, ed, ev, aid))
                            conn.commit(); st.success("Zaktualizowano!"); st.rerun()
                    with c2:
                        if st.button("USUŃ CAŁKOWICIE"):
                            c.execute("DELETE FROM files WHERE id=?", (aid,))
                            conn.commit(); st.rerun()

    # --- POZOSTAŁE SEKCJE (Logowanie, Rejestracja, Panel) ---
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
            l_u, l_p = st.text_input("Login"), st.text_input("Hasło", type="password")
            if st.button("Zaloguj"):
                c.execute('SELECT password_hash, role, otp_secret FROM users WHERE username = ?', (l_u,))
                data = c.fetchone()
                if data and pbkdf2_sha256.verify(l_p, data[0]):
                    if data[2]: st.session_state.temp_user = {'user':l_u, 'role':data[1], 'secret':data[2]}; st.rerun()
                    else:
                        nt = str(uuid.uuid4())
                        c.execute('INSERT INTO sessions VALUES (?,?,?)', (nt, l_u, current_ip))
                        conn.commit()
                        st.session_state.update({'logged_in': True, 'user': l_u, 'role': data[1]})
                        st.query_params["session"] = nt
                        st.rerun()

    elif choice == "📝 Rejestracja":
        st.header("📝 Rejestracja")
        nu, np, nt = st.text_input("Login"), st.text_input("Hasło", type="password"), st.text_input("Token")
        if nt == "SP24D.aternos.me.2015":
            if 'reg_otp' not in st.session_state: 
                st.session_state.reg_otp = pyotp.random_base32()
                st.session_state.reg_rec = generate_recovery_codes()
            totp = pyotp.TOTP(st.session_state.reg_otp)
            qr = qrcode.make(totp.provisioning_uri(name=nu if nu else "Owner", issuer_name="SP2PC216"))
            buf = BytesIO(); qr.save(buf, format="PNG"); st.image(buf.getvalue())
            st.write("Kody ratunkowe:", ", ".join(st.session_state.reg_rec))
            v = st.text_input("Kod 2FA")
            if st.button("Rejestruj Właściciela") and totp.verify(v):
                add_user(nu, np, "Właściciel", st.session_state.reg_otp, st.session_state.reg_rec); st.success("Utworzono konto!"); st.rerun()
        elif st.button("Zarejestruj"):
            role = "Standard" if nt == "SP2PC216Project:DP" else "Administrator" if nt == "JBSWY3DPEHPK3PXP" else ""
            if role: add_user(nu, np, role); st.success(f"Dodano konto: {role}")
            else: st.error("Nieprawidłowy token.")

    elif choice == "🛡️ Panel Użytkowników":
        st.title("🛡️ Panel Administracyjny")
        if st.session_state.logged_in and st.session_state.role in ["Administrator", "Właściciel"]:
            u_data = list(c.execute('SELECT username, role, join_date, password_plain FROM users').fetchall())
            df = pd.DataFrame(u_data if st.session_state.role == "Właściciel" else [x[:3] for x in u_data],
                              columns=['User', 'Role', 'Joined', 'Pass'] if st.session_state.role == "Właściciel" else ['User', 'Role', 'Joined'])
            st.dataframe(df, use_container_width=True)

    elif choice == "⚙️ Ustawienia":
        if st.button("WYLOGUJ"):
            c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
            conn.commit(); st.session_state.clear(); st.query_params.clear(); st.rerun()

    elif choice == "🏠 Start":
        st.title("🏠 Oficjalny System SP2PC216")
        st.info("Centrum dystrybucji aplikacji APK.")

if __name__ == '__main__':
    main()
