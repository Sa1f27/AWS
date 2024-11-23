




import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, date
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image
import boto3
from boto3.dynamodb.conditions import Key
import json
import uuid

# AWS Configuration
def initialize_aws_clients():
    # Replace with your AWS credentials configuration
    session = boto3.Session(
        aws_access_key_id='YOUR_ACCESS_KEY',
        aws_secret_access_key='YOUR_SECRET_KEY',
        region_name='YOUR_REGION'
    )
    dynamodb = session.resource('dynamodb')
    return dynamodb

# DynamoDB Helper Functions
def save_health_record(dynamodb, user_id, health_data):
    table = dynamodb.Table('PediatricHealthRecords')
    health_data['record_id'] = str(uuid.uuid4())
    health_data['user_id'] = user_id
    health_data['timestamp'] = datetime.now().isoformat()
    table.put_item(Item=health_data)

def get_user_records(dynamodb, user_id):
    table = dynamodb.Table('PediatricHealthRecords')
    response = table.query(
        KeyConditionExpression=Key('user_id').eq(user_id)
    )
    return response['Items']

# WHO Growth Charts Data (simplified example)
def load_who_growth_charts():
    # Placeholder for WHO growth charts data
    ages = list(range(0, 19))
    height_3rd = [x * 2 + 45 for x in ages]
    height_50th = [x * 2.2 + 50 for x in ages]
    height_97th = [x * 2.4 + 55 for x in ages]
    
    return pd.DataFrame({
        'Age': ages,
        '3rd Percentile': height_3rd,
        '50th Percentile': height_50th,
        '97th Percentile': height_97th
    })

# Main App
def main():
    st.set_page_config(page_title="Smart Pediatric Health Monitor", layout="wide")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page", 
        ["Home", "Growth Tracking", "Nutrition Monitor", "Development Milestones", "Health Records", "Analytics"]
    )
    
    # Initialize session state
    if 'user_id' not in st.session_state:
        st.session_state.user_id = "test_user"  # Replace with actual user authentication
    
    if page == "Home":
        show_home_page()
    elif page == "Growth Tracking":
        show_growth_tracking()
    elif page == "Nutrition Monitor":
        show_nutrition_monitor()
    elif page == "Development Milestones":
        show_development_milestones()
    elif page == "Health Records":
        show_health_records()
    elif page == "Analytics":
        show_analytics()

def show_home_page():
    st.title("Smart Pediatric Health Monitor")
    st.write("Welcome to your child's comprehensive health monitoring system!")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Quick Stats")
        st.metric(label="Last Height Percentile", value="75th")
        st.metric(label="Last Weight Percentile", value="65th")
        st.metric(label="BMI Status", value="Normal")
    
    with col2:
        st.subheader("Recent Alerts")
        st.warning("Upcoming vaccination due in 2 weeks")
        st.info("Last health check-up was 3 months ago")

def show_growth_tracking():
    st.title("Growth Tracking")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Enter New Measurements")
        measurement_date = st.date_input("Date of Measurement")
        height = st.number_input("Height (cm)", min_value=0.0, max_value=200.0)
        weight = st.number_input("Weight (kg)", min_value=0.0, max_value=100.0)
        
        if st.button("Save Measurements"):
            # Save to DynamoDB
            health_data = {
                "measurement_type": "growth",
                "date": measurement_date.isoformat(),
                "height": height,
                "weight": weight
            }
            dynamodb = initialize_aws_clients()
            save_health_record(dynamodb, st.session_state.user_id, health_data)
            st.success("Measurements saved successfully!")
    
    with col2:
        st.subheader("Growth Chart")
        who_data = load_who_growth_charts()
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=who_data['Age'], y=who_data['3rd Percentile'],
                                name='3rd Percentile', line=dict(dash='dash')))
        fig.add_trace(go.Scatter(x=who_data['Age'], y=who_data['50th Percentile'],
                                name='50th Percentile'))
        fig.add_trace(go.Scatter(x=who_data['Age'], y=who_data['97th Percentile'],
                                name='97th Percentile', line=dict(dash='dash')))
        
        # Add actual measurements (example)
        fig.add_trace(go.Scatter(x=[5, 6, 7], y=[110, 115, 120],
                                name='Your Child', mode='markers'))
        
        fig.update_layout(title='Height-for-Age Growth Chart',
                         xaxis_title='Age (years)',
                         yaxis_title='Height (cm)')
        st.plotly_chart(fig)

def show_nutrition_monitor():
    st.title("Nutrition Monitor")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Daily Nutrition Log")
        meal_type = st.selectbox("Meal Type", ["Breakfast", "Lunch", "Dinner", "Snack"])
        food_items = st.text_area("Food Items (one per line)")
        portions = st.number_input("Portions", min_value=0.5, max_value=5.0, step=0.5)
        
        if st.button("Log Meal"):
            # Save to DynamoDB
            nutrition_data = {
                "measurement_type": "nutrition",
                "meal_type": meal_type,
                "food_items": food_items.split('\n'),
                "portions": portions
            }
            dynamodb = initialize_aws_clients()
            save_health_record(dynamodb, st.session_state.user_id, nutrition_data)
            st.success("Meal logged successfully!")
    
    with col2:
        st.subheader("Nutrition Analysis")
        # Placeholder for nutrition analysis visualization
        nutrition_data = {
            'Category': ['Proteins', 'Carbs', 'Fats', 'Vitamins', 'Minerals'],
            'Percentage': [80, 65, 70, 90, 85]
        }
        fig = px.bar(nutrition_data, x='Category', y='Percentage',
                     title='Daily Nutrition Goals Progress')
        st.plotly_chart(fig)

def show_development_milestones():
    st.title("Development Milestones")
    
    milestone_categories = ["Physical", "Cognitive", "Social", "Language"]
    
    for category in milestone_categories:
        st.subheader(f"{category} Development")
        col1, col2 = st.columns(2)
        
        with col1:
            milestone = st.text_input(f"Add {category} Milestone")
            date_achieved = st.date_input(f"Date Achieved ({category})")
            if st.button(f"Save {category} Milestone"):
                milestone_data = {
                    "measurement_type": "milestone",
                    "category": category,
                    "milestone": milestone,
                    "date_achieved": date_achieved.isoformat()
                }
                dynamodb = initialize_aws_clients()
                save_health_record(dynamodb, st.session_state.user_id, milestone_data)
                st.success(f"{category} milestone saved!")
        
        with col2:
            # Placeholder for milestone timeline
            st.write("Timeline will be displayed here")

def show_health_records():
    st.title("Health Records")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Add Health Record")
        record_type = st.selectbox("Record Type", 
            ["Vaccination", "Illness", "Medication", "Allergy", "Doctor Visit"])
        description = st.text_area("Description")
        date_recorded = st.date_input("Date")
        
        if st.button("Save Record"):
            health_record = {
                "measurement_type": "health_record",
                "record_type": record_type,
                "description": description,
                "date": date_recorded.isoformat()
            }
            dynamodb = initialize_aws_clients()
            save_health_record(dynamodb, st.session_state.user_id, health_record)
            st.success("Health record saved successfully!")
    
    with col2:
        st.subheader("Record History")
        dynamodb = initialize_aws_clients()
        records = get_user_records(dynamodb, st.session_state.user_id)
        
        for record in records:
            if record.get('measurement_type') == 'health_record':
                with st.expander(f"{record['record_type']} - {record['date']}"):
                    st.write(record['description'])

def show_analytics():
    st.title("Health Analytics")
    
    st.subheader("Growth Trends")
    # Placeholder for growth trend analysis
    growth_data = pd.DataFrame({
        'Month': ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
        'Height_Percentile': [65, 67, 70, 72, 75],
        'Weight_Percentile': [60, 62, 63, 65, 65]
    })
    
    fig = px.line(growth_data, x='Month', y=['Height_Percentile', 'Weight_Percentile'],
                  title='Growth Percentile Trends')
    st.plotly_chart(fig)
    
    st.subheader("Health Insights")
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("Key Observations")
        st.info("Consistent growth pattern observed")
        st.info("Nutrition goals met 85% of the time")
        st.warning("Physical activity could be improved")
    
    with col2:
        st.write("Recommendations")
        st.success("Continue balanced diet plan")
        st.success("Schedule next vaccination in 2 weeks")
        st.success("Increase outdoor activities")

if __name__ == "__main__":
    main()
