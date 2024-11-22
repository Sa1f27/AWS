import os
import streamlit as st
import boto3
from datetime import datetime
import uuid
import time
import hmac
import hashlib
import base64

# Initialize session state variables
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'page' not in st.session_state:
    st.session_state.page = 'login'
if 'username' not in st.session_state:
    st.session_state.username = None
if 'verification_needed' not in st.session_state:
    st.session_state.verification_needed = False

# AWS Configuration
AWS_REGION = st.secrets["AWS_REGION"]
USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
AWS_ACCESS_KEY = st.secrets["AWS_ACCESS_KEY"]
AWS_SECRET_KEY = st.secrets["AWS_SECRET_KEY"]

# Initialize AWS clients
cognito_client = boto3.client(
    'cognito-idp',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

# Page configuration
st.set_page_config(
    page_title="MedTech Pro",
    page_icon="🏥",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS with improved styling
st.markdown("""
    <style>
        .stButton > button {
            width: 100%;
            background-color: #0083B8;
            color: white;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            margin: 0.5rem 0;
        }
        .stTextInput > div > div > input {
            border-radius: 5px;
        }
        .main > div {
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: white;
            margin: 1rem 0;
        }
        .css-1d391kg {
            padding: 1rem;
        }
        .stAlert {
            margin: 1rem 0;
        }
    </style>
""", unsafe_allow_html=True)

def generate_secret_hash(username):
    """Generate SECRET_HASH for Cognito authentication"""
    message = username + CLIENT_ID
    dig = hmac.new(
        key=bytes(CLIENT_SECRET, 'utf-8'),
        msg=bytes(message, 'utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def authenticate_user(username, password):
    """Authenticate user with improved error handling"""
    try:
        secret_hash = generate_secret_hash(username)
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        return True, response['AuthenticationResult']['AccessToken']
    except cognito_client.exceptions.UserNotConfirmedException:
        return False, 'UserNotConfirmed'
    except cognito_client.exceptions.NotAuthorizedException:
        return False, 'InvalidCredentials'
    except Exception as e:
        return False, str(e)

def register_user(username, password, email, user_details):
    """Register user with improved error handling"""
    try:
        secret_hash = generate_secret_hash(username)
        
        # Register in Cognito
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=secret_hash,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        
        # Save to DynamoDB
        table = dynamodb.Table('UserDetails')
        table.put_item(
            Item={
                'username': username,
                'email': email,
                **user_details,
                'created_at': datetime.now().isoformat()
            }
        )
        return True, None
    except cognito_client.exceptions.UsernameExistsException:
        return False, "Username already exists"
    except Exception as e:
        return False, str(e)

def verify_user(username, code):
    """Verify user with improved error handling"""
    try:
        secret_hash = generate_secret_hash(username)
        cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=code,
            SecretHash=secret_hash
        )
        return True, None
    except cognito_client.exceptions.CodeMismatchException:
        return False, "Invalid verification code"
    except Exception as e:
        return False, str(e)

def login_page():
    """Improved login page with better state management"""
    st.title("🏥 MedTech Pro")
    
    if st.session_state.verification_needed:
        verification_code = st.text_input("Verification Code")
        if st.button("Verify Email"):
            success, error = verify_user(st.session_state.username, verification_code)
            if success:
                st.success("Email verified! Please login.")
                st.session_state.verification_needed = False
                st.session_state.username = None
                time.sleep(2)
                st.rerun()
            else:
                st.error(f"Verification failed: {error}")
    else:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted and username and password:
                success, result = authenticate_user(username, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.token = result
                    st.session_state.page = "dashboard"
                    st.success("Login successful!")
                    time.sleep(1)
                    st.rerun()
                elif result == 'UserNotConfirmed':
                    st.warning("Please verify your email first.")
                    st.session_state.verification_needed = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid credentials")

        if st.button("Create New Account"):
            st.session_state.page = "registration"
            st.rerun()

def registration_page():
    """Improved registration page with better validation"""
    st.title("🏥 Create Account")
    
    with st.form("registration_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("Username*")
            password = st.text_input("Password*", type="password", 
                help="Must be at least 8 characters with numbers and special characters")
            email = st.text_input("Email*")
            full_name = st.text_input("Full Name*")
            phone = st.text_input("Phone Number*")
            
        with col2:
            dob = st.date_input("Date of Birth*")
            blood_group = st.selectbox("Blood Group*", 
                ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"])
            address = st.text_area("Address*")
            emergency_contact = st.text_input("Emergency Contact*")
        
        medical_conditions = st.text_area("Existing Medical Conditions (Optional)")
        
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if all([username, password, email, full_name, phone, address, emergency_contact]):
                user_details = {
                    'full_name': full_name,
                    'phone': phone,
                    'dob': dob.isoformat(),
                    'blood_group': blood_group,
                    'address': address,
                    'emergency_contact': emergency_contact,
                    'medical_conditions': medical_conditions or "None"
                }
                
                success, error = register_user(username, password, email, user_details)
                if success:
                    st.success("Registration successful! Please check your email for verification code.")
                    st.session_state.verification_needed = True
                    st.session_state.username = username
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error(f"Registration failed: {error}")
            else:
                st.error("Please fill in all required fields")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

def dashboard_page():
    """Improved dashboard with better data display"""
    if not st.session_state.authenticated:
        st.session_state.page = "login"
        st.rerun()
        return

    user_details = get_user_details(st.session_state.username)
    
    if user_details:
        st.title(f"Welcome, {user_details['full_name']} 👋")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Personal Information")
            st.write(f"📧 Email: {user_details['email']}")
            st.write(f"📱 Phone: {user_details['phone']}")
            st.write(f"🩸 Blood Group: {user_details['blood_group']}")
        
        with col2:
            st.subheader("Emergency Contact")
            st.write(f"👤 Contact: {user_details['emergency_contact']}")
            st.write(f"📍 Address: {user_details['address']}")

        st.subheader("Medical Records")
        records = get_medical_records(st.session_state.username)
        
        if records:
            for record in records:
                with st.expander(f"Record from {record['created_at'][:10]}"):
                    st.write(record)
        else:
            st.info("No medical records found")

        if st.button("Log Out"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

def get_user_details(username):
    """Get user details with error handling"""
    table = dynamodb.Table('UserDetails')
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item')
    except Exception as e:
        st.error(f"Error fetching user details: {str(e)}")
        return None

def get_medical_records(username):
    """Get medical records with error handling"""
    table = dynamodb.Table('MedicalRecords')
    try:
        response = table.query(
            IndexName='username-index',  # Make sure this index exists in DynamoDB
            KeyConditionExpression='username = :username',
            ExpressionAttributeValues={':username': username}
        )
        return response.get('Items', [])
    except Exception as e:
        st.error(f"Error fetching medical records: {str(e)}")
        return []

def main():
    """Main app flow with improved state management"""
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "registration":
        registration_page()
    elif st.session_state.page == "dashboard":
        dashboard_page()

if __name__ == "__main__":
    main()
