import os
import streamlit as st
import boto3
from jose import jwt
from datetime import datetime
import uuid

# Use environment variables for AWS configuration
REGION = os.getenv('AWS_REGION')
USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')

# Initialize Boto3 clients
cognito_client = boto3.client(
    'cognito-idp',
    region_name=REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

def authenticate_user(username, password):
    """Authenticate a user using Cognito."""
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
    except cognito_client.exceptions.NotAuthorizedException:
        return None
    except cognito_client.exceptions.UserNotConfirmedException:
        return 'UserNotConfirmed'

def register_user(username, password, email, user_details):
    """Register a new user using Cognito and save additional details to DynamoDB."""
    try:
        # Register user in Cognito
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': user_details['full_name']},
                {'Name': 'custom:phone_number', 'Value': user_details['phone']},
            ]
        )
        
        # Save additional user details to DynamoDB
        table = dynamodb.Table('UserDetails')
        table.put_item(
            Item={
                'username': username,
                'email': email,
                'full_name': user_details['full_name'],
                'phone': user_details['phone'],
                'date_of_birth': user_details['dob'],
                'address': user_details['address'],
                'emergency_contact': user_details['emergency_contact'],
                'medical_conditions': user_details['medical_conditions'],
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
        )
        return True
    except Exception as e:
        st.error(f"Registration error: {str(e)}")
        return False

def save_medical_record(username, record_type, description):
    """Save a medical record to DynamoDB."""
    table = dynamodb.Table('MedicalRecords')
    try:
        table.put_item(
            Item={
                'record_id': str(uuid.uuid4()),
                'username': username,
                'record_type': record_type,
                'description': description,
                'timestamp': datetime.now().isoformat()
            }
        )
        return True
    except Exception as e:
        st.error(f"Error saving medical record: {str(e)}")
        return False

def get_user_details(username):
    """Fetch user details from DynamoDB."""
    table = dynamodb.Table('UserDetails')
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item', None)
    except Exception as e:
        st.error(f"Error fetching user details: {str(e)}")
        return None

def get_medical_records(username):
    """Fetch user's medical records from DynamoDB."""
    table = dynamodb.Table('MedicalRecords')
    try:
        response = table.query(
            KeyConditionExpression='username = :username',
            ExpressionAttributeValues={':username': username}
        )
        return response.get('Items', [])
    except Exception as e:
        st.error(f"Error fetching medical records: {str(e)}")
        return []

def main():
    st.title("MedTech App")
    
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Create a New Account")
        with st.form("registration_form"):
            new_username = st.text_input("Username*")
            new_password = st.text_input("Password*", type='password')
            new_email = st.text_input("Email*")
            full_name = st.text_input("Full Name*")
            phone = st.text_input("Phone Number*")
            dob = st.date_input("Date of Birth*")
            address = st.text_area("Address*")
            emergency_contact = st.text_input("Emergency Contact Number*")
            medical_conditions = st.text_area("Existing Medical Conditions (if any)")
            
            submit_button = st.form_submit_button("Register")
            
            if submit_button:
                if all([new_username, new_password, new_email, full_name, phone, address, emergency_contact]):
                    user_details = {
                        'full_name': full_name,
                        'phone': phone,
                        'dob': dob.isoformat(),
                        'address': address,
                        'emergency_contact': emergency_contact,
                        'medical_conditions': medical_conditions
                    }
                    
                    if register_user(new_username, new_password, new_email, user_details):
                        st.success("Registration successful! Please check your email for the verification code.")
                        verification_code = st.text_input("Enter verification code:")
                        if st.button("Verify Email"):
                            try:
                                cognito_client.confirm_sign_up(
                                    ClientId=CLIENT_ID,
                                    Username=new_username,
                                    ConfirmationCode=verification_code
                                )
                                st.success("Email verified successfully! You can now login.")
                            except Exception as e:
                                st.error("Verification failed. Please try again.")
                else:
                    st.error("Please fill in all required fields.")

    elif choice == "Login":
        st.subheader("Login to Your Account")
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')

        if st.button("Login"):
            token = authenticate_user(username, password)
            if token == 'UserNotConfirmed':
                st.warning("Please verify your email first.")
                verification_code = st.text_input("Enter verification code:")
                if st.button("Verify Email"):
                    try:
                        cognito_client.confirm_sign_up(
                            ClientId=CLIENT_ID,
                            Username=username,
                            ConfirmationCode=verification_code
                        )
                        st.success("Email verified successfully! You can now login.")
                    except Exception as e:
                        st.error("Verification failed. Please try again.")
            elif token:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password.")

    if st.session_state.authenticated:
        show_dashboard(st.session_state.username)

def show_dashboard(username):
    """Display user dashboard with medical information"""
    st.sidebar.button("Logout", on_click=lambda: setattr(st.session_state, 'authenticated', False))
    
    # Fetch and display user details
    user_details = get_user_details(username)
    if user_details:
        st.header(f"Welcome, {user_details['full_name']}!")
        
        # Personal Information Section
        with st.expander("Personal Information", expanded=True):
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Email:**", user_details['email'])
                st.write("**Phone:**", user_details['phone'])
                st.write("**Date of Birth:**", user_details['date_of_birth'])
            with col2:
                st.write("**Address:**", user_details['address'])
                st.write("**Emergency Contact:**", user_details['emergency_contact'])
        
        # Medical Records Section
        st.subheader("Medical Records")
        
        # Add new medical record
        with st.expander("Add New Medical Record"):
            record_type = st.selectbox("Record Type", 
                ["Consultation", "Prescription", "Lab Test", "Vaccination", "Surgery", "Other"])
            description = st.text_area("Description")
            if st.button("Save Record"):
                if save_medical_record(username, record_type, description):
                    st.success("Medical record saved successfully!")
                    st.experimental_rerun()
        
        # Display existing medical records
        records = get_medical_records(username)
        if records:
            for record in records:
                with st.expander(f"{record['record_type']} - {record['timestamp'][:10]}"):
                    st.write("**Type:**", record['record_type'])
                    st.write("**Description:**", record['description'])
                    st.write("**Date:**", record['timestamp'])
        else:
            st.info("No medical records found.")
        
        # Medical Conditions Section
        if user_details.get('medical_conditions'):
            with st.expander("Medical Conditions"):
                st.write(user_details['medical_conditions'])

if __name__ == "__main__":
    main()
