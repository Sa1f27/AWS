## Overview

This management web application built using **Streamlit**, **AWS Cognito**, and **AWS DynamoDB**. The app enables user registration, authentication, and management of medical records with a user-friendly interface. It leverages **AWS services** to ensure secure and scalable data handling.

## Features

- **User Authentication**: User registration, email verification, and login using AWS Cognito.
- **User Profile Management**: Store and manage personal and emergency contact information.
- **Medical Record Storage**: Save and view medical records in AWS DynamoDB.
- **Secure Data Handling**: AWS Cognito for user authentication and DynamoDB for secure data storage.
- **Easy-to-use Interface**: Built using Streamlit for a clean and interactive user experience.

## Technologies Used

- **Streamlit** - Frontend framework for building the UI.
- **AWS Cognito** - Authentication service for user management.
- **AWS DynamoDB** - NoSQL database for storing user and medical records.
- **Python** - Core language for development.
- **Boto3** - AWS SDK for Python to interact with AWS services.

## Prerequisites

Make sure you have the following before starting the setup:

1. **Python 3.7+** installed on your machine.
2. **AWS Account** with appropriate permissions for Cognito and DynamoDB.
3. **Streamlit** installed (`pip install streamlit`).
4. AWS IAM user with access keys configured to interact with Cognito and DynamoDB.

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your_username/medtech-pro.git
cd medtech-pro
```

### 2. Install Required Packages

Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

### 3. AWS Setup

#### **Step 3.1 - Cognito User Pool Setup**
1. Go to the AWS Console and navigate to **Cognito**.
2. Create a new **User Pool**:
   - Add attributes: `email`, `username`, and any other attributes you need.
   - Enable self-registration and email verification.
   - Note down the **User Pool ID**.
3. Create a new **App Client**:
   - Disable the Client Secret if not using a server-based app.
   - Note down the **Client ID**.

#### **Step 3.2 - DynamoDB Setup**
1. Go to the AWS Console and navigate to **DynamoDB**.
2. Create two tables:
   - **UserDetails**:
     - Partition Key: `username` (String)
   - **MedicalRecords**:
     - Partition Key: `username` (String)
     - Sort Key: `record_id` (String)

#### **Step 3.3 - IAM User Setup**
1. Create an IAM user with programmatic access.
2. Attach policies for full access to **Cognito** and **DynamoDB**.
3. Generate an **Access Key ID** and **Secret Access Key**.

### 4. Configuration

Create a file named `secrets.toml` in the `.streamlit` directory with the following content:

```toml
[secrets]
AWS_REGION = "YOUR_REGION"  # e.g., "us-east-1"
USER_POOL_ID = "YOUR_USER_POOL_ID"
CLIENT_ID = "YOUR_CLIENT_ID"
AWS_ACCESS_KEY = "YOUR_ACCESS_KEY"
AWS_SECRET_KEY = "YOUR_SECRET_KEY"
```

Replace the placeholders with your actual AWS configuration.

## Running the Application

To start the Streamlit application, run the following command:

```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`.

## Directory Structure

```
aws/
├── app.py                  # Main application file
├── requirements.txt        # Python dependencies
├── .streamlit/
│   └── secrets.toml        # AWS Configuration
└── README.md               # Documentation
```

## Usage

### **Login Page**
1. Users can log in using their credentials.
2. If the account is not verified, a verification code can be entered to confirm the email.

### **Registration Page**
1. New users can register by providing:
   - Username
   - Password
   - Email
   - Personal details (Full Name, Phone, etc.)
2. After registration, a verification code is sent to the user's email for verification.

### **Dashboard**
1. Users can view and update their **Profile** information.
2. **Records** tab to view the Dashboard.
3. **Add New Record** tab to input new records.

## Troubleshooting

### **Common Issues**
- **NotAuthorizedException**: Ensure that the Client ID in Cognito does not require a secret unless it's explicitly handled in the code.
- **DynamoDB Access Denied**: Check if the IAM user has the correct policies attached.
- **Login/Registration Issues**: Ensure the AWS region is correctly configured and matches the region in Cognito and DynamoDB.

### **Debugging Tips**
- Use Streamlit's `st.error` and `st.warning` to display error messages for troubleshooting.
- Check AWS CloudWatch for any detailed error logs related to Cognito or DynamoDB operations.

### Additional Tips
- Keep your `secrets.toml` file out of version control (`.gitignore`) to prevent exposing sensitive data.
- Ensure the `requirements.txt` file includes all dependencies, such as:
  ```plaintext
  streamlit
  boto3
  python-dotenv
  ```
- Use virtual environments to manage Python dependencies efficiently.

This README should give a comprehensive overview of how to set up and run your MedTech Pro application, ensuring that anyone following the guide can replicate your setup successfully.
