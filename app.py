import os
import streamlit as st
import boto3
from datetime import datetime
import uuid
import time

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
        # Register in Cognito
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
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
                            st.experimental_rerun()
                elif token:
                    st.session_state.token = token
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.success("Login successful!")
                    time.sleep(1)
                    st.experimental_rerun()
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
                            st.session_state.page = "login"
                            st.experimental_rerun()
            else:
                st.error("Please fill in all required fields")

def dashboard_page():
    """Display user dashboard"""
    user_details = get_user_details(st.session_state.username)
    
    if user_details:
        st.title(f"Welcome, {user_details['full_name']}!")
        
        # Navigation
        tabs = st.tabs(["Profile", "Medical Records", "New Record"])
        
        # Profile Tab
        with tabs[0]:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Personal Information")
                st.write(f"**Email:** {user_details['email']}")
                st.write(f"**Phone:** {user_details['phone']}")
                st.write(f"**DOB:** {user_details['date_of_birth']}")
                st.write(f"**Blood Group:** {user_details['blood_group']}")
            
            with col2:
                st.subheader("Emergency Information")
                st.write(f"**Address:** {user_details['address']}")
                st.write(f"**Emergency Contact:** {user_details['emergency_contact']}")
                if user_details.get('medical_conditions'):
                    st.write("**Medical Conditions:**")
                    st.write(user_details['medical_conditions'])
        
        # Medical Records Tab
        with tabs[1]:
            st.subheader("Medical History")
            records = get_medical_records(st.session_state.username)
            
            if records:
                for record in records:
                    with st.expander(f"{record['record_type']} - {record['created_at'][:10]}"):
                        st.write(f"**Type:** {record['record_type']}")
                        st.write(f"**Description:** {record['description']}")
                        if record.get('attachments'):
                            st.write("**Attachments:** Available")
            else:
                st.info("No medical records found")
        
        # New Record Tab
        with tabs[2]:
            st.subheader("Add Medical Record")
            with st.form("new_record_form"):
                record_type = st.selectbox("Record Type*", 
                    ["Consultation", "Prescription", "Lab Test", "Vaccination", 
                     "Surgery", "Allergies", "Other"])
                description = st.text_area("Description*")
                
                submitted = st.form_submit_button("Save Record")
                if submitted:
                    if description:
                        record_data = {
                            'record_type': record_type,
                            'description': description
                        }
                        if save_medical_record(st.session_state.username, record_data):
                            st.success("Record saved successfully!")
                            time.sleep(1)
                            st.experimental_rerun()
                    else:
                        st.error("Please fill in all required fields")

def main():
    """Main application logic"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    
    # Logout button in header
    if st.session_state.authenticated:
        if st.button("Logout", key="logout"):
            st.session_state.clear()
            st.experimental_rerun()
    
    # Navigation
    if not st.session_state.authenticated:
        col1, col2 = st.columns([6,1])
        with col2:
            if st.session_state.page == 'login':
                if st.button("Register"):
                    st.session_state.page = 'registration'
                    st.experimental_rerun()
            else:
                if st.button("Login"):
                    st.session_state.page = 'login'
                    st.experimental_rerun()
        
        if st.session_state.page == 'login':
            login_page()
        else:
            registration_page()
    else:
        dashboard_page()

if __name__ == "__main__":
    main()
