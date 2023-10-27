# -*- coding: utf-8 -*-
"""HACKX.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/13PhvS9RucBMO-DViNrLIu1aaYttGWiT0
"""

import streamlit as st
import pickle
import pandas as pd
from extract_features import ExtractFeatures
from PIL import Image

# image2 = Image.open('muj logo.png')
# st.image(image2, width=200)

# image = Image.open('hackxlogowhite.png')
# # st.image(image, width=200)
# col1, col2, col3 = st.columns([20, 10, 0.1])
# col2.image(image, use_column_width=True)

image2 = Image.open('muj logo.png')
image = Image.open('hackxlogowhite.png')

col1, col2, col3 = st.columns([0.001, 8, 3])

with col2:
    st.image(image2, width=200)

with col3:
    st.image(image, width=200)

st.markdown(
    "<div style='display: flex; align-items: center; margin-bottom: -35px;'>"
    "<h1 style='color:#F862FC; margin-center: 10px;'>404 Not Found,</h1>"
    "</div>"
    "<h1 style='color:black; margin-center: 10px;'>But We Found It!</h1>"
    "</div>",
    unsafe_allow_html=True
)

# st.markdown(
#     "<div style='display: flex; align-items: center; margin-bottom: -35px;'>"
#     "<h1 style='color:#F862FC; margin-center: 10px;'>yoU aRe reaL</h1>",
#     unsafe_allow_html=True
# )

# image=Image.open('phising1.jpeg')
# width=750
# height=700
# image_new=image.resize((width,height))
# st.image(image_new)

@st.cache_resource
def get_model():
    """
    Loads the phishing URL detection model from a pickle file.

    This function reads and loads a pickled file containing the classifier.

    Returns:
        object: The loaded phishing URL detection model.

    Note:
        The model should be saved in a file named 'phishing_url_detector.pkl'.
        XGBoost module must be installed before using the file.
    """
    with open('phishing_url_detector.pkl', 'rb') as pickle_model:
        phishing_url_detector = pickle.load(pickle_model)
    return phishing_url_detector

# Takes in user input
input_url = st.text_area("Are you sure your 'bank' sent that link?")


if input_url != "":

    # Extracts features from the URL and converts it into a dataframe
    features_url = ExtractFeatures().url_to_features(url=input_url)
    features_dataframe = pd.DataFrame.from_dict([features_url])
    features_dataframe = features_dataframe.fillna(-1)
    features_dataframe = features_dataframe.astype(int)

    st.write("Snooping around...")
    st.cache_data.clear()
    prediction_str = ""

    # Predict outcome using extracted features
#     try:
#         phishing_url_detector = get_model()
#         prediction = phishing_url_detector.predict(features_dataframe)
#         if prediction == int(True):
#             prediction_str = 'This website might be malicious!'
#         elif prediction == int(False):
#             prediction_str = 'Website is safe to proceed!'
#         else:
#             prediction_str = ''
#         st.write(prediction_str)
#         st.write(features_dataframe)

#     except Exception as e:
#         print(e)
#         st.error("Not sure, what went wrong. We'll get back to you shortly!")

# else:
#     st.write("")

import requests

# Function to check if a URL returns a 404 error
def check_404(url):
    try:
        response = requests.head(url)  # Use HEAD request for faster checking
        return response.status_code == 404
    except requests.RequestException:
        return False

# Function to brute force valid URLs
def brute_force_url(base_url):
    # This is a simple wordlist for the sake of demonstration.
    # In real scenarios, you might read from a .txt file.
    wordlist = ['about', 'contact', 'login', 'signup', 'user', 'admin','404']

    found_urls = []
    for word in wordlist:
        # Construct new URL to check
        new_url = base_url + "/" + word
        if not check_404(new_url):
            found_urls.append(new_url)

    return found_urls

if input_url != "":
    # Initialize a variable to store the final URL
    final_url = input_url

    # Check if "404" is in the input URL and initiate brute force
    if "404" in input_url:
        st.write(f"{input_url} Status: 404 (Not Found) - Initiating Brute Force")

        # Try to brute force the correct URL by modifying the input_url
        possible_urls = brute_force_url(input_url)
        if possible_urls:
            final_url = possible_urls[0]  # Use the first valid URL found
            st.write(f"Brute-forced URL: {final_url}")
        else:
            st.write("No valid URLs found based on the wordlist.")
    else:
        try:
            r = requests.head(input_url)
            if r.status_code == 404:
                st.write(f"{input_url} Status: 404 (Not Found) - Initiating Brute Force")
                # Try to brute force the correct URL by modifying the input_url
                possible_urls = brute_force_url(input_url)
                if possible_urls:
                    final_url = possible_urls[0]  # Use the first valid URL found
                    st.write(f"Brute-forced URL: {final_url}")
                else:
                    st.write("No valid URLs found based on the wordlist.")
            else:
                st.write(f"{input_url} Status: 200 (OK)")
        except Exception as e:
            st.write(f"{final_url} NA FAILED TO CONNECT {str(e)}")

    # Continue with phishing detection
    # Extract features from the URL and convert it into a dataframe
    features_url = ExtractFeatures().url_to_features(url=final_url)
    features_dataframe = pd.DataFrame.from_dict([features_url])
    features_dataframe = features_dataframe.fillna(-1)
    features_dataframe = features_dataframe.astype(int)

    st.write("Snooping around...")
    st.cache_data.clear()
    prediction_str = ""

    # Predict outcome using extracted features
    try:
        phishing_url_detector = get_model()
        prediction = phishing_url_detector.predict(features_dataframe)
        if prediction == int(True):
            prediction_str = 'This website might be malicious!'
        elif prediction == int(False):
            prediction_str = 'Website is safe to proceed!'
        else:
            prediction_str = ''
        st.write(prediction_str)
        st.write(features_dataframe)
    except Exception as e:
        print(e)
        st.error("Not sure what went wrong. We'll get back to you shortly!")

else:
    st.write("")
st.markdown("### *Our Approach*")
st.markdown("To tackle this challenge, we leveraged classical machine learning techniques, including Data Exploration, Data Cleaning, Feature Engineering, Model Building, and Model Testing. Our comprehensive approach involved experimenting with different machine learning algorithms to identify the most suitable ones for this particular case.")
st.markdown("### *Key Features*")
st.markdown("- URL-Based Features: We extracted insightful features from the URL itself to capture potential indicators of phishing behavior.")
st.markdown("- Domain-Based Features: By analyzing the domain properties, we uncovered valuable attributes that help distinguish between genuine and malicious domains.")
st.markdown("- Page-Based Features: We delved into the contents of web pages associated with each domain, uncovering unique features that shed light on their legitimacy.")
st.markdown("- Content-Based Features: Leveraging the textual content present on web pages, we derived additional features that contribute to the overall detection accuracy.")

st.markdown("### *Results*")
st.markdown("Our solution provides a robust and reliable method for predicting whether a domain is authentic or fake. By utilizing the power of machine learning, we have created a model that can effectively discern the telltale signs of phishing attempts, enabling users to make informed decisions and avoid potential security breaches.")

