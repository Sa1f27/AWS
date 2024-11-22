import os
import streamlit as st
import boto3
from datetime import datetime
import uuid
import time
import hmac
import hashlib
import base64

# Use environment variables for AWS configuration
AWS_REGION = st.secrets["AWS_REGION"]
USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
AWS_ACCESS_KEY = st.secrets["AWS_ACCESS_KEY"]
AWS_SECRET_KEY = st.secrets["AWS_SECRET_KEY"]

# Initialize Boto3 clients using these variables
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

# Custom CSS
st.markdown("""
    <style>
        .stButton button {
            width: 100%;
            background-color: #0083B8;
            color: white;
            border-radius: 5px;
        }
        .stTextInput > div > div > input {
            border-radius: 5px;
        }
        .main > div {
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: white;
        }
        .css-1d391kg {
            padding: 1rem 1rem 2rem;
        }
        .st-emotion-cache-1gulkj5 {
            margin-bottom: 2rem;
        }
    </style>
""", unsafe_allow_html=True)

def generate_secret_hash(username, client_id, client_secret):
    """
    Generate SECRET_HASH using HMACSHA256(username + client_id, client_secret)
    """
    message = username + client_id
    secret_hash = hmac.new(
        key=bytes(client_secret, 'utf-8'),
        msg=bytes(message, 'utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(secret_hash).decode('utf-8')
    
def authenticate_user(username, password):
    """Authenticate user with Cognito"""
    try:
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        return response['AuthenticationResult']['AccessToken']
    except cognito_client.exceptions.UserNotConfirmedException:
        return 'UserNotConfirmed'
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return None

def register_user(username, password, email, user_details):
    """Register new user in Cognito and DynamoDB"""
    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, st.secrets["CLIENT_SECRET"])  # Generate SECRET_HASH

        # Register in Cognito
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=secret_hash,  # Add SECRET_HASH
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
                'full_name': user_details['full_name'],
                'phone': user_details['phone'],
                'date_of_birth': user_details['dob'],
                'blood_group': user_details['blood_group'],
                'address': user_details['address'],
                'emergency_contact': user_details['emergency_contact'],
                'medical_conditions': user_details['medical_conditions'],
                'created_at': datetime.now().isoformat()
            }
        )
        return True
    except Exception as e:
        st.error(f"Registration error: {str(e)}")
        return False

def verify_user(username, code):
    """Verify user email with confirmation code"""
    try:
        cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=code
        )
        return True
    except Exception as e:
        st.error(f"Verification error: {str(e)}")
        return False

def save_medical_record(username, record_data):
    """Save medical record to DynamoDB"""
    table = dynamodb.Table('MedicalRecords')
    try:
        record_id = str(uuid.uuid4())
        table.put_item(
            Item={
                'record_id': record_id,
                'username': username,
                **record_data,
                'created_at': datetime.now().isoformat()
            }
        )
        return True
    except Exception as e:
        st.error(f"Error saving record: {str(e)}")
        return False

def get_user_details(username):
    """Get user details from DynamoDB"""
    table = dynamodb.Table('UserDetails')
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item')
    except Exception as e:
        st.error(f"Error fetching user details: {str(e)}")
        return None

def get_medical_records(username):
    """Get user's medical records from DynamoDB"""
    table = dynamodb.Table('MedicalRecords')
    try:
        response = table.query(
            KeyConditionExpression='username = :username',
            ExpressionAttributeValues={':username': username}
        )
        return response.get('Items', [])
    except Exception as e:
        st.error(f"Error fetching records: {str(e)}")
        return []

def login_page():
    """Display login page"""
    st.title("🏥 MedTech Pro")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if username and password:
                token = authenticate_user(username, password)
                if token == 'UserNotConfirmed':
                    st.warning("Please verify your email first.")
                    verification_code = st.text_input("Verification Code")
                    if st.button("Verify Email"):
                        if verify_user(username, verification_code):
                            st.success("Email verified! Please login again.")
                            time.sleep(2)
                            st.session_state.page = 'login'  # Update page to login after verification
                            st.session_state.clear()  # Clear session state to reset app
                elif token:
                    st.session_state.token = token
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.success("Login successful!")
                    time.sleep(1)
                    st.session_state.page = "dashboard"  # Redirect to dashboard after successful login
                    st.session_state.clear()  # Clear session state to reset app
                else:
                    st.error("Invalid credentials")
            else:
                st.error("Please fill in all fields")

def registration_page():
    """Display registration page"""
    st.title("🏥 Create Account")
    
    with st.form("registration_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("Username*")
            password = st.text_input("Password*", type="password")
            email = st.text_input("Email*")
            full_name = st.text_input("Full Name*")
            phone = st.text_input("Phone Number*")
            
        with col2:
            dob = st.date_input("Date of Birth*")
            blood_group = st.selectbox("Blood Group*", 
                ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"])
            address = st.text_area("Address*")
            emergency_contact = st.text_input("Emergency Contact*")
        
        medical_conditions = st.text_area("Existing Medical Conditions")
        
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
                    'medical_conditions': medical_conditions
                }
                
                if register_user(username, password, email, user_details):
                    st.success("Registration successful! Please check your email for verification code.")
                    verification_code = st.text_input("Enter verification code")
                    if st.button("Verify Email"):
                        if verify_user(username, verification_code):
                            st.success("Email verified! You can now login.")
                            time.sleep(2)
                            st.session_state.page = "login"  # Update page to login after registration
                            st.session_state.clear()  # Clear session state to reset app
            else:
                st.error("Please fill in all required fields")

def dashboard_page():
    """Display user dashboard"""
    user_details = get_user_details(st.session_state.username)
    
    if user_details:
        st.title(f"Welcome, {user_details['full_name']}")
        st.subheader("Your Medical Records")
        records = get_medical_records(st.session_state.username)
        
        for record in records:
            st.write(record)

        # Option to log out
        if st.button("Log Out"):
            st.session_state.clear()  # Clear session state to reset app
            st.session_state.page = "login"  # Redirect to login page

def main():
    """Main function for app flow"""
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "registration":
        registration_page()
    elif st.session_state.page == "dashboard":
        dashboard_page()

if __name__ == "__main__":
    main()
