import os
import streamlit as st
import boto3
from jose import jwt

# Use environment variables for AWS configuration
REGION = os.getenv('AWS_REGION')
USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')

# Initialize Boto3 client using environment variables
cognito_client = boto3.client(
    'cognito-idp',
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

def register_user(username, password, email):
    """Register a new user using Cognito."""
    try:
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                }
            ]
        )
        return True
    except cognito_client.exceptions.UsernameExistsException:
        return False

def confirm_user(username, confirmation_code):
    """Confirm a user's registration using a verification code."""
    try:
        cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code
        )
        return True
    except cognito_client.exceptions.CodeMismatchException:
        return False
    except cognito_client.exceptions.ExpiredCodeException:
        return False

def resend_confirmation(username):
    """Resend the confirmation code to the user's email."""
    try:
        cognito_client.resend_confirmation_code(
            ClientId=CLIENT_ID,
            Username=username
        )
        return True
    except Exception as e:
        return False

# Streamlit UI
def main():
    st.title("MedTech App")
    
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Create a New Account")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type='password')
        new_email = st.text_input("Email")

        if st.button("Register"):
            if new_email:
                if register_user(new_username, new_password, new_email):
                    st.success("Registration successful! Please check your email for the OTP.")
                    # Ask for OTP input to confirm the user
                    otp = st.text_input("Enter the OTP sent to your email:")
                    if st.button("Confirm OTP"):
                        if confirm_user(new_username, otp):
                            st.success("Your account has been confirmed! You can now log in.")
                        else:
                            st.error("Invalid or expired OTP. Please try again.")
                            if st.button("Resend OTP"):
                                if resend_confirmation(new_username):
                                    st.success("OTP has been resent. Please check your email.")
                                else:
                                    st.error("Failed to resend OTP.")
                else:
                    st.error("User already exists or registration failed.")
            else:
                st.error("Please enter a valid email address.")

    elif choice == "Login":
        st.subheader("Login to Your Account")
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')

        if st.button("Login"):
            token = authenticate_user(username, password)
            if token == 'UserNotConfirmed':
                st.warning("User is not confirmed. Please check your email for the OTP.")
                otp = st.text_input("Enter the OTP sent to your email:")
                if st.button("Confirm OTP"):
                    if confirm_user(username, otp):
                        st.success("Your account has been confirmed! You can now log in.")
                    else:
                        st.error("Invalid or expired OTP. Please try again.")
                        if st.button("Resend OTP"):
                            if resend_confirmation(username):
                                st.success("OTP has been resent. Please check your email.")
                            else:
                                st.error("Failed to resend OTP.")
            elif token:
                st.success("Login successful!")
                show_dashboard(username)
            else:
                st.error("Invalid username or password.")

def show_dashboard(username):
    """Display user information"""
    st.header(f"Welcome, {username}!")
    st.subheader("User Medical History")
    # Fetch user data from DynamoDB
    dynamodb = boto3.resource(
        'dynamodb',
        region_name=REGION,
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    table = dynamodb.Table('UserHistory')
    response = table.get_item(Key={'username': username})
    
    if 'Item' in response:
        medical_data = response['Item'].get('medical_data', 'No data available.')
        st.write(f"Medical Data: {medical_data}")
    else:
        st.write("No medical history available.")

if __name__ == "__main__":
    main()
