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

def register_user(username, password):
    """Register a new user using Cognito."""
    try:
        cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
        )
        return True
    except cognito_client.exceptions.UsernameExistsException:
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

        if st.button("Register"):
            if register_user(new_username, new_password):
                st.success("Registration successful! You can log in now.")
            else:
                st.error("User already exists or registration failed.")
    
    elif choice == "Login":
        st.subheader("Login to Your Account")
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')

        if st.button("Login"):
            token = authenticate_user(username, password)
            if token:
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
