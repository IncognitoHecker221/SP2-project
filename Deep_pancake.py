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
conn = sqlite3.connect('projekt_szkolny_v7.db', check_same_thread=False)
c = conn.cursor()


def create_db():
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, 
                  join_date TEXT, password_plain TEXT, otp_secret TEXT, recovery_codes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS warnings
                 (target_user TEXT, sender TEXT, reason TEXT, date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT, username TEXT, ip_address TEXT)''')
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

    # --- EKRAN WERYFIKACJI 2FA / RECOVERY ---
    if st.session_state.temp_user:
        st.header("🔐 Weryfikacja Logowania")

        if not st.session_state.recovery_mode:
            st.write(f"Witaj **{st.session_state.temp_user['user']}**. Wprowadź kod z aplikacji Google Authenticator.")
            otp_code = st.text_input("Kod 2FA", max_chars=6)

            col1, col2 = st.columns([1, 4])
            with col1:
                if st.button("Zaloguj"):
                    totp = pyotp.TOTP(st.session_state.temp_user['secret'])
                    if totp.verify(otp_code):
                        u, r = st.session_state.temp_user['user'], st.session_state.temp_user['role']
                        new_token = str(uuid.uuid4())
                        c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_token, u, current_ip))
                        conn.commit()
                        st.session_state.update({'logged_in': True, 'user': u, 'role': r, 'temp_user': None})
                        st.query_params["session"] = new_token
                        st.rerun()
                    else:
                        st.error("Błędny kod!")
            with col2:
                if st.button("Użyj kodu odzyskiwania"):
                    st.session_state.recovery_mode = True
                    st.rerun()
        else:
            st.warning("Tryb Odzyskiwania: Wprowadź jeden ze swoich 10-znakowych kodów ratunkowych.")
            rec_code = st.text_input("Kod Odzyskiwania").strip()
            if st.button("Zaloguj i wyłącz 2FA"):
                c.execute('SELECT recovery_codes FROM users WHERE username = ?', (st.session_state.temp_user['user'],))
                db_codes = c.fetchone()[0].split(",")
                if rec_code in db_codes:
                    # Logowanie sukces, wyłączamy 2FA (bezpieczeństwo)
                    u, r = st.session_state.temp_user['user'], st.session_state.temp_user['role']
                    c.execute('UPDATE users SET otp_secret = NULL, recovery_codes = NULL WHERE username = ?', (u,))
                    new_token = str(uuid.uuid4())
                    c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_token, u, current_ip))
                    conn.commit()
                    st.session_state.update(
                        {'logged_in': True, 'user': u, 'role': r, 'temp_user': None, 'recovery_mode': False})
                    st.query_params["session"] = new_token
                    st.success("Zalogowano! 2FA zostało wyłączone. Skonfiguruj je ponownie w ustawieniach.")
                    st.rerun()
                else:
                    st.error("Nieprawidłowy kod odzyskiwania.")
            if st.button("Powrót do 2FA"):
                st.session_state.recovery_mode = False
                st.rerun()
        return

    # --- LOGOWANIE / REJESTRACJA ---
    if not st.session_state.logged_in:
        menu = st.sidebar.radio("Wybierz", ["Logowanie", "Rejestracja"])

        if menu == "Rejestracja":
            st.header("📝 Rejestracja")
            new_u = st.text_input("Login")
            new_p = st.text_input("Hasło", type="password")
            token = st.text_input("Token")

            if token == "SP24D.aternos.me.2015":  # WŁAŚCICIEL
                st.warning("⚠️ Właściciel: Skonfiguruj 2FA i ZAPISZ KODY RATUNKOWE!")
                if 'reg_otp_secret' not in st.session_state:
                    st.session_state.reg_otp_secret = pyotp.random_base32()
                    st.session_state.reg_recovery = generate_recovery_codes()

                totp = pyotp.TOTP(st.session_state.reg_otp_secret)
                qr = qrcode.make(totp.provisioning_uri(name=new_u, issuer_name="SP2PC216"))
                buf = BytesIO();
                qr.save(buf, format="PNG")
                st.image(buf.getvalue(), caption="Zeskanuj w Google Authenticator")

                st.info("🔑 TWOJE KODY ODZYSKIWANIA (ZAPISZ JE!):")
                st.write(", ".join([f"`{c}`" for c in st.session_state.reg_recovery]))

                ver_code = st.text_input("Kod z aplikacji")
                if st.button("Finalizuj rejestrację Właściciela"):
                    if totp.verify(ver_code):
                        add_user(new_u, new_p, "Właściciel", st.session_state.reg_otp_secret,
                                 st.session_state.reg_recovery)
                        st.success("Konto założone!")
                        st.rerun()
                    else:
                        st.error("Błędny kod 2FA.")
            else:
                if st.button("Zarejestruj"):
                    role = "Standard" if token == "SP2PC216Project:DP" else "Administrator" if token == "JBSWY3DPEHPK3PXP" else ""
                    if role:
                        add_user(new_u, new_p, role)
                        st.success(f"Zarejestrowano jako {role}")
                    else:
                        st.error("Zły token.")

        else:
            st.header("🔑 Logowanie")
            u = st.text_input("Użytkownik")
            p = st.text_input("Hasło", type="password")
            if st.button("Zaloguj"):
                c.execute('SELECT password_hash, role, otp_secret FROM users WHERE username = ?', (u,))
                data = c.fetchone()
                if data and pbkdf2_sha256.verify(p, data[0]):
                    if data[2]:
                        st.session_state.temp_user = {'user': u, 'role': data[1], 'secret': data[2]}
                        st.rerun()
                    else:
                        new_token = str(uuid.uuid4())
                        c.execute('INSERT INTO sessions VALUES (?,?,?)', (new_token, u, current_ip))
                        conn.commit()
                        st.session_state.update({'logged_in': True, 'user': u, 'role': data[1]})
                        st.query_params["session"] = new_token
                        st.rerun()
                else:
                    st.error("Błąd logowania.")

    else:
        # --- PANEL PO ZALOGOWANIU ---
        st.sidebar.title(f"Witaj, {st.session_state.user}")
        page = st.sidebar.selectbox("Menu", ["Główna", "Pomoc Techniczna", "Panel Zarządzania", "Ustawienia"])

        if page == "Ustawienia":
            st.title("⚙️ Ustawienia")
            c.execute('SELECT otp_secret, recovery_codes FROM users WHERE username = ?', (st.session_state.user,))
            secret, codes = c.fetchone()

            if not secret:
                if st.button("Aktywuj 2FA"):
                    st.session_state.setup_otp = pyotp.random_base32()
                    st.session_state.setup_recovery = generate_recovery_codes()

                if 'setup_otp' in st.session_state:
                    totp = pyotp.TOTP(st.session_state.setup_otp)
                    qr = qrcode.make(totp.provisioning_uri(name=st.session_state.user, issuer_name="SP2PC216"))
                    buf = BytesIO();
                    qr.save(buf, format="PNG");
                    st.image(buf.getvalue())
                    st.write("Kody ratunkowe:", ", ".join([f"`{c}`" for c in st.session_state.setup_recovery]))
                    conf = st.text_input("Kod z telefonu")
                    if st.button("Potwierdź włączenie 2FA"):
                        if totp.verify(conf):
                            c.execute('UPDATE users SET otp_secret=?, recovery_codes=? WHERE username=?',
                                      (st.session_state.setup_otp, ",".join(st.session_state.setup_recovery),
                                       st.session_state.user))
                            conn.commit();
                            st.rerun()
            else:
                st.success("2FA jest włączone.")
                if st.session_state.role != "Właściciel" and st.button("Wyłącz 2FA"):
                    c.execute('UPDATE users SET otp_secret=NULL, recovery_codes=NULL WHERE username=?',
                              (st.session_state.user,))
                    conn.commit();
                    st.rerun()

            if st.button("WYLOGUJ"):
                c.execute('DELETE FROM sessions WHERE username=?', (st.session_state.user,))
                conn.commit();
                st.session_state.clear();
                st.query_params.clear();
                st.rerun()

        # Pozostałe podstrony (Główna, Pomoc, Panel) działają tak jak wcześniej
        elif page == "Główna":
            st.title("🏠 Strona Główna"); st.info("Współwłaściciel: Agnieszka Terebus-Wieczorkiewicz")
        elif page == "Pomoc Techniczna":
            st.title("🎧 Pomoc"); st.chat_input("Napisz wiadomość...")
        elif page == "Panel Zarządzania":
            if st.session_state.role in ["Administrator", "Właściciel"]:
                st.title("🛡️ Administracja")
                all_u = list(c.execute('SELECT username, role, join_date, password_plain FROM users').fetchall())
                df = pd.DataFrame(all_u if st.session_state.role == "Właściciel" else [x[:3] for x in all_u],
                                  columns=['User', 'Role', 'Date',
                                           'Pass'] if st.session_state.role == "Właściciel" else ['User', 'Role',
                                                                                                  'Date'])
                st.dataframe(df, use_container_width=True)
            else:
                st.error("Brak dostępu")


if __name__ == '__main__':
    main()