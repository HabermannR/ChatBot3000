import streamlit as st
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import anthropic
import firebase_admin
from firebase_admin import credentials, firestore
import datetime
import os

# Initialize Firebase Admin SDK (if not already initialized)
if not firebase_admin._apps:
    try:
        # Create a dictionary from the secrets
        firebase_creds = {
            "type": st.secrets["firebase"]["type"],
            "project_id": st.secrets["firebase"]["project_id"],
            "private_key_id": st.secrets["firebase"]["private_key_id"],
            "private_key": st.secrets["firebase"]["private_key"],
            "client_email": st.secrets["firebase"]["client_email"],
            "client_id": st.secrets["firebase"]["client_id"],
            "auth_uri": st.secrets["firebase"]["auth_uri"],
            "token_uri": st.secrets["firebase"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["firebase"]["auth_provider_x509_cert_url"],
            "client_x509_cert_url": st.secrets["firebase"]["client_x509_cert_url"],
            "universe_domain": st.secrets["firebase"]["universe_domain"]
        }
        cred = credentials.Certificate(firebase_creds)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        st.error(f"Firebase initialization error: {str(e)}")


def initialize_db():
    """Initialize Firestore database connection"""
    try:
        return firestore.client()
    except Exception as e:
        st.error(f"Database connection error: {str(e)}")
        return None


def get_user_chats(db, user_email):
    """Fetch all chat sessions for a user"""
    try:
        chats_ref = db.collection('chats').where('user_email', '==', user_email).stream()
        return [{
            'id': chat.id,
            'title': chat.to_dict().get('title', 'Untitled Chat'),
            'created_at': chat.to_dict().get('created_at', datetime.datetime.now()),
            'updated_at': chat.to_dict().get('updated_at', datetime.datetime.now())
        } for chat in chats_ref]
    except Exception as e:
        st.error(f"Error fetching chats: {str(e)}")
        return []


def get_chat_history(db, chat_id):
    """Fetch messages for a specific chat session"""
    try:
        messages_ref = db.collection('chats').document(chat_id).collection('messages').order_by('timestamp').stream()
        return [message.to_dict() for message in messages_ref]
    except Exception as e:
        st.error(f"Error fetching chat history: {str(e)}")
        return []


def create_new_chat(db, user_email, title=None):
    """Create a new chat session for the user"""
    try:
        chat_ref = db.collection('chats').document()
        timestamp = datetime.datetime.now()
        chat_data = {
            'user_email': user_email,
            'title': title or f"New Chat ({timestamp.strftime('%Y-%m-%d %H:%M')})",
            'created_at': timestamp,
            'updated_at': timestamp
        }
        chat_ref.set(chat_data)
        return chat_ref.id
    except Exception as e:
        st.error(f"Error creating new chat: {str(e)}")
        return None


def save_message(db, chat_id, message):
    """Save a message to the database"""
    try:
        message['timestamp'] = datetime.datetime.now()
        message_ref = db.collection('chats').document(chat_id).collection('messages').document()
        message_ref.set(message)

        # Update the chat's updated_at timestamp
        db.collection('chats').document(chat_id).update({
            'updated_at': message['timestamp']
        })

        return True
    except Exception as e:
        st.error(f"Error saving message: {str(e)}")
        return False


def update_chat_title(db, chat_id, title):
    """Update the title of a chat session"""
    try:
        db.collection('chats').document(chat_id).update({
            'title': title,
            'updated_at': datetime.datetime.now()
        })
        return True
    except Exception as e:
        st.error(f"Error updating chat title: {str(e)}")
        return False


def delete_chat(db, chat_id):
    """Delete a chat session and all its messages"""
    try:
        # Delete all messages in the chat
        messages_ref = db.collection('chats').document(chat_id).collection('messages').stream()
        for message in messages_ref:
            message.reference.delete()

        # Delete the chat document
        db.collection('chats').document(chat_id).delete()
        return True
    except Exception as e:
        st.error(f"Error deleting chat: {str(e)}")
        return False


def main():
    st.title("Secure Chat Application")

    # Read configuration from secrets.toml
    client_id = st.secrets["google"]["client_id"]
    client_secret = st.secrets["google"]["client_secret"]
    redirect_uri = st.secrets["google"]["redirect_uri"]  # Set this appropriately in secrets
    anthropic_api_key = st.secrets["anthropic"]["api_key"]

    # Initialize session state variables if they don't exist
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'current_chat_id' not in st.session_state:
        st.session_state.current_chat_id = None
    if 'chat_list' not in st.session_state:
        st.session_state.chat_list = []

    # Initialize database
    db = initialize_db()

    # Check for authorization code in URL using st.query_params
    if "code" in st.query_params:
        auth_code = st.query_params["code"]
        try:
            # Exchange auth code for tokens
            token_endpoint = "https://oauth2.googleapis.com/token"

            token_data = {
                'code': auth_code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }

            token_response = requests.post(token_endpoint, data=token_data)
            token_response_data = token_response.json()

            if 'id_token' in token_response_data:
                # Verify the token
                id_info = id_token.verify_oauth2_token(
                    token_response_data['id_token'],
                    google_requests.Request(),
                    client_id
                )

                st.session_state.user_info = id_info
                # Clear the URL parameters
                st.query_params.clear()
            else:
                st.error("Failed to obtain ID token")

        except Exception as e:
            os.write(1, f"Authentication error: {str(e)}".encode())
            st.error("Authentication failed. Please try again.")  # Show generic message

    ALLOWED_EMAIL = st.secrets["google"]["allowed_users"]  # Your email in secrets
    #if st.session_state.user_info.get('email') != ALLOWED_EMAIL:
    #    st.error("Access denied. Only the app owner can log in.")
    #    st.session_state.user_info = None
    #    return

    # Show login button or user info
    if st.session_state.user_info and db:
        user_email = st.session_state.user_info.get('email')
        st.sidebar.success(f"Logged in as: {st.session_state.user_info.get('name', 'User')}")
        st.sidebar.write(f"Email: {user_email}")

        if st.sidebar.button("Logout"):
            st.session_state.user_info = None
            st.session_state.current_chat_id = None
            st.session_state.chat_list = []
            st.rerun()

        # Fetch user's chats
        st.session_state.chat_list = get_user_chats(db, user_email)

        # Sidebar for chat management
        st.sidebar.title("Your Chats")

        # Create new chat button
        if st.sidebar.button("New Chat"):
            new_chat_id = create_new_chat(db, user_email)
            if new_chat_id:
                st.session_state.current_chat_id = new_chat_id
                st.session_state.chat_list = get_user_chats(db, user_email)
                st.rerun()

        # Display chat list
        for chat in st.session_state.chat_list:
            col1, col2 = st.sidebar.columns([3, 1])
            with col1:
                if st.button(chat['title'], key=f"chat_{chat['id']}"):
                    st.session_state.current_chat_id = chat['id']
                    st.rerun()
            with col2:
                if st.button("🗑️", key=f"del_{chat['id']}", help="Delete this chat"):
                    if delete_chat(db, chat['id']):
                        if st.session_state.current_chat_id == chat['id']:
                            st.session_state.current_chat_id = None
                        st.session_state.chat_list = get_user_chats(db, user_email)
                        st.rerun()

        # Main chat area
        if st.session_state.current_chat_id:
            current_chat = next((c for c in st.session_state.chat_list if c['id'] == st.session_state.current_chat_id),
                                None)

            # Chat title with edit option
            col1, col2 = st.columns([3, 1])
            with col1:
                st.subheader(current_chat['title'] if current_chat else "New Chat")
            with col2:
                if st.button("Edit Title", key="edit_title"):
                    st.session_state.editing_title = True

            # Edit title form
            if st.session_state.get('editing_title', False):
                with st.form("edit_title_form"):
                    new_title = st.text_input("New title", value=current_chat['title'] if current_chat else "")
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("Save"):
                            if update_chat_title(db, st.session_state.current_chat_id, new_title):
                                st.session_state.chat_list = get_user_chats(db, user_email)
                                st.session_state.editing_title = False
                                st.rerun()
                    with col2:
                        if st.form_submit_button("Cancel"):
                            st.session_state.editing_title = False
                            st.rerun()

            # Display chat history
            chat_history = get_chat_history(db, st.session_state.current_chat_id)

            for message in chat_history:
                if message["role"] == "user":
                    st.chat_message("user").write(message["content"])
                else:
                    st.chat_message("assistant").write(message["content"])

            # Chat input
            user_input = st.chat_input("Ask Claude something...")

            if user_input:
                # Display user message
                st.chat_message("user").write(user_input)

                # Save user message to database
                user_message = {"role": "user", "content": user_input}
                save_message(db, st.session_state.current_chat_id, user_message)

                # Get Claude response
                client = anthropic.Anthropic(api_key=anthropic_api_key)

                # Get system prompt from secrets
                system_prompt = st.secrets["anthropic"]["system_prompt"]

                # Get updated chat history after saving the user message
                updated_chat_history = get_chat_history(db, st.session_state.current_chat_id)
                messages = [
                    {"role": message["role"], "content": message["content"]}
                    for message in updated_chat_history
                ]

                with st.chat_message("assistant"):
                    message_placeholder = st.empty()
                    full_response = ""

                    try:
                        response = client.messages.create(
                            model="claude-3-7-sonnet-20250219",
                            max_tokens=20000,
                            temperature=1,
                            system=system_prompt,
                            messages=messages
                        )
                        full_response = response.content[0].text
                        message_placeholder.markdown(full_response)
                    except Exception as e:
                        full_response = f"Error: {str(e)}"
                        message_placeholder.error(full_response)

                # Save assistant response to database
                assistant_message = {"role": "assistant", "content": full_response}
                save_message(db, st.session_state.current_chat_id, assistant_message)

                # Update the first message as the title if this is a new chat with default title
                if len(updated_chat_history) <= 1 and current_chat and "New Chat" in current_chat['title']:
                    # Use the first ~30 chars of user message as title
                    new_title = user_input[:30] + ("..." if len(user_input) > 30 else "")
                    update_chat_title(db, st.session_state.current_chat_id, new_title)
                    st.session_state.chat_list = get_user_chats(db, user_email)
                    st.rerun()
        else:
            # No chat selected
            st.info("Select a chat from the sidebar or create a new one to get started.")


    else:
        st.write("Please sign in to access the full application.")
        
        # Create Google Sign-In URL with prompt parameter
        auth_url = "https://accounts.google.com/o/oauth2/auth"
        scope = "openid email profile"
        auth_endpoint = f"{auth_url}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&access_type=offline&prompt=select_account"
        
        # Use Streamlit's built-in link functionality
        if st.button("Sign in with Google"):
            js = f"""
            <script>
                window.location.href = "{auth_endpoint}";
            </script>
            """
            st.components.v1.html(js, height=1)


if __name__ == "__main__":
    main()
