# app.py
import streamlit as st
import sqlite3
import hashlib
import uuid
import smtplib
from email.mime.text import MIMEText
from requests_oauthlib import OAuth2Session
import urllib.parse
from langgraph_database_backend import chatbot, retrieve_all_threads
from langchain_core.messages import HumanMessage
import uuid as _uuid
from streamlit_cookies_manager import EncryptedCookieManager

cookies = EncryptedCookieManager(
    prefix="langgraph_chatbot",     
    password="super-secret-key"    
)
if not cookies.ready():
    st.stop() 

DB = "chatbot.db"
OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_USERINFO = "https://www.googleapis.com/oauth2/v1/userinfo"
#OAUTH_SCOPE = ["openid", "email", "profile"]
OAUTH_SCOPE = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]
def get_db_conn():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT UNIQUE,
        password TEXT,
        token TEXT,
        verified INTEGER DEFAULT 0
    );
    ''')
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_via_smtp(to_email: str, subject: str, body: str) -> bool:
    # Use Streamlit secrets if provided
    try:
        smtp_conf = st.secrets["smtp"]
        host = smtp_conf["host"]
        port = int(smtp_conf.get("port", 465))
        username = smtp_conf["username"]
        password = smtp_conf["password"]

        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = to_email

        with smtplib.SMTP_SSL(host, port) as server:
            server.login(username, password)
            server.sendmail(username, [to_email], msg.as_string())
        return True
    except Exception as e:
        # If smtp not configured or failure, return False
        print("SMTP send failed:", e)
        return False

def make_verification_link(token: str, purpose: str="verify"):
    # purpose can be 'verify' or 'reset'
    app_url = st.secrets.get("google", {}).get("app_url") if "google" in st.secrets else None
    if not app_url:
        app_url = "http://localhost:8501/"
    # ensure trailing slash
    if not app_url.endswith("/"):
        app_url = app_url + "/"
    return f"{app_url}?{purpose}={urllib.parse.quote(token)}"

# --------------------------
# User DB functions
# --------------------------
def create_user(username: str, email: str, password: str):
    token = str(uuid.uuid4())
    hashed = hash_password(password)
    conn = get_db_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password, token, verified) VALUES (?, ?, ?, ?, 0)",
                  (username, email, hashed, token))
        conn.commit()
        user_id = c.lastrowid
    except sqlite3.IntegrityError as e:
        conn.close()
        return None, "duplicate"
    conn.close()
    return {"id": user_id, "username": username, "email": email, "token": token}, None

def get_user_by_email(email: str):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, password, token, verified FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_token(token: str):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, password, token, verified FROM users WHERE token=?", (token,))
    row = c.fetchone()
    conn.close()
    return row

def verify_user(token: str):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET verified=1, token=NULL WHERE token=?", (token,))
    conn.commit()
    changes = conn.total_changes
    conn.close()
    return changes > 0

def set_reset_token(email: str):
    token = str(uuid.uuid4())
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET token=? WHERE email=?", (token, email))
    conn.commit()
    conn.close()
    return token

def reset_password(token: str, new_password: str):
    hashed = hash_password(new_password)
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET password=?, token=NULL WHERE token=?", (hashed, token))
    conn.commit()
    changes = conn.total_changes
    conn.close()
    return changes > 0

def login_with_email(email: str, password: str):
    hashed = hash_password(password)
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, verified FROM users WHERE email=? AND password=?", (email, hashed))
    row = c.fetchone()
    conn.close()
    return row  # None if not found

# --------------------------
# Helper: user-scoped threads
# --------------------------
def user_prefix(user_id: int):
    return f"user{user_id}:"

def generate_thread_id_for_user(user_id: int):
    return user_prefix(user_id) + str(_uuid.uuid4())

def add_thread_local(thread_id):
    if "chat_threads" not in st.session_state:
        st.session_state["chat_threads"] = []
    if thread_id not in st.session_state["chat_threads"]:
        st.session_state["chat_threads"].append(thread_id)

def get_all_threads_for_user(user_id: int):
    # retrieve_all_threads() returns all thread ids saved by langgraph backend.
    all_threads = retrieve_all_threads()
    pref = user_prefix(user_id)
    return [t for t in all_threads if str(t).startswith(pref)]

def strip_user_prefix(thread_id: str):
    pref = user_prefix(st.session_state["user"]["id"])
    if str(thread_id).startswith(pref):
        return str(thread_id)[len(pref):]
    return thread_id


# --------------------------
# Google OAuth helpers
# --------------------------
def build_google_oauth_session(state=None):
    client_id = st.secrets["google"]["client_id"]
    redirect_uri = st.secrets["google"]["app_url"]
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=OAUTH_SCOPE, state=state)

def get_auth_url_and_state():
    oauth = build_google_oauth_session()
    auth_url, state = oauth.authorization_url(
        OAUTH_AUTH_URL,
        access_type="offline",
        prompt="consent",
    )
    return auth_url, state

def fetch_google_token(code, state):
    client_id = st.secrets["google"]["client_id"]
    client_secret = st.secrets["google"]["client_secret"]
    redirect_uri = st.secrets["google"]["app_url"]
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=OAUTH_SCOPE, state=state)
    token = oauth.fetch_token(OAUTH_TOKEN_URL, client_secret=client_secret, code=code)
    return token

def get_google_userinfo(token):
    # token is dict
    oauth = OAuth2Session(st.secrets["google"]["client_id"], token=token)
    resp = oauth.get(OAUTH_USERINFO)
    return resp.json()

# --------------------------
# Initialize DB & Session
# --------------------------
init_db()

if "user" not in st.session_state:
    st.session_state["user"] = None

if st.session_state["user"] is None and "auth_user" in cookies and cookies["auth_user"]!="":
    user_id = int(cookies["auth_user"])
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, verified FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row and row[3] == 1:  # must be verified
        st.session_state["user"] = {"id": row[0], "username": row[1], "email": row[2]}


if "message_history" not in st.session_state:
    st.session_state["message_history"] = []

if "thread_id" not in st.session_state:
    st.session_state["thread_id"] = None

if "chat_threads" not in st.session_state:
    st.session_state["chat_threads"] = []

# --------------------------
# Handle query params for verify / reset / oauth callback
# --------------------------
query_params = st.query_params

# Email verification link clicked: ?verify=<token>
if "verify" in query_params:
    print(query_params)
    token = query_params.get("verify")
    ok = verify_user(token)
    if ok:
        st.success("Email verified! You can now log in.")
    else:
        st.error("Invalid or expired token.")
    # st.query_params

# Password reset link clicked: ?reset=<token>
if "reset" in query_params:
    token = query_params.get("reset")
    st.session_state["pw_reset_token"] = token
    # st.query_params

# Google OAuth callback: Google will redirect to app_url with ?code=...&state=...
if "code" in query_params and "state" in query_params and cookies.get("oauth_flow") == "1":
    code = query_params.get("code")
    state = query_params.get("state")
    print(code, state)
    cookies["oauth_flow"] = ""  # reset
    cookies.save()
    # exchange code for token
    try:
        token = fetch_google_token(code, state)
        info = get_google_userinfo(token)
        email = info.get("email")
        username = info.get("name") or email.split("@")[0]
        print(info)
        # create or login user; mark verified
        row = get_user_by_email(email)
        if row is None:
            # create user with random password and mark verified
            conn = get_db_conn()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, token, verified) VALUES (?, ?, ?, NULL, 1)",
                      (username, email, hash_password(str(uuid.uuid4()))))
            conn.commit()
            user_id = c.lastrowid
            conn.close()
            st.session_state["user"] = {"id": user_id, "username": username, "email": email}
            cookies["auth_user"] = str(user_id)   # Store user_id in cookie
            cookies.save()
        else:
            # row: id, username, email, password, token, verified
            st.session_state["user"] = {"id": row[0], "username": row[1], "email": row[2]}
            cookies["auth_user"] = str(row[0])   # Store user_id in cookie
            cookies.save()
            # ensure verified
            conn = get_db_conn()
            c = conn.cursor()
            c.execute("UPDATE users SET verified=1 WHERE id=?", (row[0],))
            conn.commit()
            conn.close()
        st.success(f"Google login successful: {st.session_state['user']['email']}")
    except Exception as e:
        st.error("Google OAuth failed: " + str(e))
    finally:
        # st.query_params
        pass
        
        

# --------------------------
# Authentication UI (Sidebar)
# --------------------------
st.sidebar.title("Kshitij Chatbot")

if st.session_state["user"] is None:
    auth_mode = st.sidebar.selectbox("Choose", ["Login", "Signup", "Forgot Password"])
    if auth_mode == "Signup":
        st.sidebar.subheader("Create an account")
        new_username = st.sidebar.text_input("Username", key="su_username")
        new_email = st.sidebar.text_input("Email", key="su_email")
        new_password = st.sidebar.text_input("Password", type="password", key="su_pass")
        if st.sidebar.button("Signup"):
            if not new_username or not new_email or not new_password:
                st.sidebar.error("All fields required")
            else:
                user, err = create_user(new_username, new_email, new_password)
                if err == "duplicate":
                    st.sidebar.error("Email already exists")
                else:
                    # send verification email
                    verification_link = make_verification_link(user["token"], purpose="verify")
                    body = f"Hi {new_username},<br/><br/>Click the link to verify your email:<br/><a href='{verification_link}'>{verification_link}</a><br/><br/>"
                    sent = send_email_via_smtp(new_email, "Verify your email", body)
                    if sent:
                        st.sidebar.success("Signup successful — verification email sent.")
                    else:
                        st.sidebar.warning("Invalid Email ID — couldn't send email.")
                        #st.sidebar.markdown(f"[Verify]({verification_link})")
    elif auth_mode == "Login":
        st.sidebar.subheader("Login")
        email = st.sidebar.text_input("Email", key="li_email")
        password = st.sidebar.text_input("Password", type="password", key="li_pass")
        if st.sidebar.button("Login"):
            row = login_with_email(email, password)
            if row is None:
                st.sidebar.error("Invalid credentials")
            else:
                user_id, username, email_db, verified = row[0], row[1], row[2], row[3]
                if verified != 1:
                    st.sidebar.warning("Please verify your email first.")
                else:
                    st.session_state["user"] = {"id": user_id, "username": username, "email": email_db}
                    cookies["auth_user"] = str(user_id)   # Store user_id in cookie
                    cookies.save()
                    st.sidebar.success(f"Logged in as {username}")
    else:  # Forgot Password
        st.sidebar.subheader("Forgot Password")
        fp_email = st.sidebar.text_input("Enter your registered email", key="fp_email")
        if st.sidebar.button("Send reset link"):
            row = get_user_by_email(fp_email)
            if row is None:
                st.sidebar.error("Email not registered")
            else:
                token = set_reset_token(fp_email)
                reset_link = make_verification_link(token, purpose="reset")
                body = f"Hi,<br/>Click to reset your password:<br/><a href='{reset_link}'>{reset_link}</a><br/>"
                sent = send_email_via_smtp(fp_email, "Reset your password", body)
                if sent:
                    st.sidebar.success("Reset email sent")
                else:
                    st.sidebar.warning("Invalid Email ID: Couldn't send email.")
                    #st.sidebar.markdown(f"[Reset password link]({reset_link})")

    # Google OAuth button
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Or sign in with Google**")
    if st.sidebar.button("Continue with Google"):
        # start OAuth: create authorization URL and show link (we open in new tab)
        try:
            auth_url, state = get_auth_url_and_state()
            cookies["oauth_flow"] = "1"
            #cookies["oauth_state"] = state
            cookies.save()
            st.write(f'<meta http-equiv="refresh" content="0; url={auth_url}">', unsafe_allow_html=True)
        except Exception as e:
            print(e)
            st.sidebar.error("Google OAuth setup missing or invalid. Check secrets.")

else:
    st.sidebar.success(f"Logged in as {st.session_state['user']['username']}")
    if st.sidebar.button("Logout"):
        
        cookies["auth_user"]= ""  # 🔑 Clear cookie
        cookies.save()
        del st.session_state["user"]
        del st.session_state["message_history"]
        del st.session_state["thread_id"]
        st.rerun()
        

# --------------------------
# If user arrived via reset token (from query param), show reset form
# --------------------------
if "pw_reset_token" in st.session_state and st.session_state["pw_reset_token"]:
    st.subheader("Reset password")
    t = st.session_state["pw_reset_token"]
    new_pw = st.text_input("Enter new password", type="password", key="reset_pw")
    if st.button("Set new password"):
        ok = reset_password(t, new_pw)
        if ok:
            st.success("Password reset successful — you can now log in.")
            st.session_state["pw_reset_token"] = None
        else:
            st.error("Invalid/expired token.")

# ----------------------------------------------------
# If logged in → show the chatbot (user-scoped)
# ----------------------------------------------------
if st.session_state["user"] is not None:
    user = st.session_state["user"]
    st.title(f"Kshitij Chatbot — {user['username']}")
    # Sidebar: new chat
    if st.sidebar.button("New Chat"):
        # create user-scoped thread id
        tid = generate_thread_id_for_user(user["id"])
        st.session_state["thread_id"] = tid
        add_thread_local(tid)
        # add to langgraph state as well by calling add_thread (we have a local add_thread function above)
        # message history reset
        st.session_state["message_history"] = []

    st.sidebar.header("My Conversations")
    # load threads from backend, filter to user
    threads = get_all_threads_for_user(user["id"])
    # also include threads created in this session
    threads = list(dict.fromkeys((st.session_state.get("chat_threads", []) + threads)))  # preserve order + unique
    for thread_id in threads[::-1]:
        if st.sidebar.button(str(thread_id)):
            st.session_state["thread_id"] = thread_id
            # load conversation from langgraph
            CONFIG = {'configurable': {'thread_id': thread_id}}
            state = chatbot.get_state(config=CONFIG)
            messages = state.values.get("messages", [])
            temp_messages = []
            for msg in messages:
                if isinstance(msg, HumanMessage):
                    role = "user"
                else:
                    role = "assistant"
                temp_messages.append({'role': role, 'content': msg.content})
            st.session_state["message_history"] = temp_messages

    # If no thread selected, create one
    if not st.session_state.get("thread_id"):
        st.session_state["thread_id"] = generate_thread_id_for_user(user["id"])
        add_thread_local(st.session_state["thread_id"])

    # show chat history
    for message in st.session_state["message_history"]:
        with st.chat_message(message['role']):
            st.text(message['content'])

    user_input = st.chat_input("Type here...")
    if user_input:
        st.session_state["message_history"].append({'role': 'user', 'content': user_input})
        with st.chat_message('user'):
            st.text(user_input)

        CONFIG = {'configurable': {'thread_id': st.session_state['thread_id']}}
        # stream response
        with st.chat_message('assistant'):
            ai_message = st.write_stream(
                message_chunk.content for message_chunk, metadata in chatbot.stream(
                    {'messages': [HumanMessage(content=user_input)]},
                    config=CONFIG,
                    stream_mode='messages'
                )
            )
        st.session_state['message_history'].append({'role': 'assistant', 'content': ai_message})

    # show small footer
    st.markdown("---")
    st.caption("Logged in. How can i help you today.")

else:
    st.title("Kshitij Chatbot")
    st.write("Please sign up or log in to start chatting.")

