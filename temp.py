import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from axe_selenium_python import Axe
import pandas as pd
from sklearn.ensemble import IsolationForest
import time
import json

def scrape_website(url):
    driver = webdriver.Chrome()
    driver.get(url)
    
    # Wait for the page to load
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    
    # Find links
    links = [a.get_attribute('href') for a in driver.find_elements(By.TAG_NAME, "a") if a.get_attribute('href')]
    
    # Find input fields
    inputs = [i.get_attribute('name') for i in driver.find_elements(By.TAG_NAME, "input") if i.get_attribute('name')]
    
    # Find buttons
    buttons = [b.text or b.get_attribute('value') for b in driver.find_elements(By.TAG_NAME, "button") + driver.find_elements(By.XPATH, "//input[@type='submit']")]
    
    driver.quit()
    
    return links, inputs, buttons

def run_automated_tests(url):
    driver = webdriver.Chrome()
    driver.get(url)
    
    results = []
    
    # Wait for page load
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "txtUsername")))
        load_time = driver.execute_script('return performance.timing.loadEventEnd - performance.timing.navigationStart')
        results.append(("Page Load", url, "Pass", f"Loaded in {load_time}ms"))
    except TimeoutException:
        results.append(("Page Load", url, "Fail", "Timed out waiting for page to load"))
        driver.quit()
        return results

    # Test login fields
    for field in ["txtUsername", "txtPassword"]:
        try:
            element = driver.find_element(By.ID, field)
            element.send_keys("test_input")
            results.append(("Input", field, "Pass", "Input accepted"))
        except Exception as e:
            results.append(("Input", field, "Fail", f"Error: {str(e)}"))

    # Test login button
    try:
        login_button = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "btnLogin")))
        login_button.click()
        results.append(("Button", "Login", "Pass", "Button clicked"))
        # Check for error message or successful login
        try:
            error_message = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "lblMessage")))
            results.append(("Login Validation", "Error Message", "Pass", error_message.text))
        except TimeoutException:
            results.append(("Login Validation", "Error Message", "Fail", "No error message found, possible successful login"))
    except Exception as e:
        results.append(("Button", "Login", "Fail", f"Error: {str(e)}"))

    # Test forgot password
    try:
        forgot_password = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "btnForgotPassword")))
        forgot_password.click()
        results.append(("Button", "Forgot Password", "Pass", "Button clicked"))
        # Check if password reset page loaded
        try:
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "txtEmail")))
            results.append(("Navigation", "Password Reset Page", "Pass", "Password reset page loaded"))
        except TimeoutException:
            results.append(("Navigation", "Password Reset Page", "Fail", "Password reset page not loaded"))
    except Exception as e:
        results.append(("Button", "Forgot Password", "Fail", f"Error: {str(e)}"))

    # Test Google login integration
    try:
        google_login = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "btnLoginWithGoogle")))
        google_login.click()
        results.append(("Button", "Google Login", "Pass", "Button clicked"))
        # Check if Google login page loaded
        try:
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "identifierId")))
            results.append(("Navigation", "Google Login Page", "Pass", "Google login page loaded"))
        except TimeoutException:
            results.append(("Navigation", "Google Login Page", "Fail", "Google login page not loaded"))
    except Exception as e:
        results.append(("Button", "Google Login", "Fail", f"Error: {str(e)}"))

    # Check for CAPTCHA
    try:
        captcha = driver.find_element(By.ID, "captchaImg")
        results.append(("Security", "CAPTCHA", "Pass", "CAPTCHA detected"))
    except NoSuchElementException:
        results.append(("Security", "CAPTCHA", "Pass", "No CAPTCHA detected"))

    # Check for secure connection
    if driver.current_url.startswith("https"):
        results.append(("Security", "HTTPS", "Pass", "Secure connection detected"))
    else:
        results.append(("Security", "HTTPS", "Fail", "Insecure connection detected"))

    # Check for secure cookie attributes
    cookies = driver.get_cookies()
    for cookie in cookies:
        if cookie.get('secure'):
            results.append(("Security", f"Cookie {cookie['name']}", "Pass", "Secure flag set"))
        else:
            results.append(("Security", f"Cookie {cookie['name']}", "Fail", "Secure flag not set"))
        if cookie.get('httpOnly'):
            results.append(("Security", f"Cookie {cookie['name']}", "Pass", "HttpOnly flag set"))
        else:
            results.append(("Security", f"Cookie {cookie['name']}", "Fail", "HttpOnly flag not set"))

    # Responsive design tests
    window_sizes = [(1920, 1080), (1366, 768), (360, 640)]  # Desktop, Laptop, Mobile
    for width, height in window_sizes:
        driver.set_window_size(width, height)
        time.sleep(1)  # Allow time for responsive changes
        try:
            login_form = driver.find_element(By.ID, "loginForm")
            if login_form.is_displayed():
                results.append(("Responsive Design", f"{width}x{height}", "Pass", "Login form visible"))
            else:
                results.append(("Responsive Design", f"{width}x{height}", "Fail", "Login form not visible"))
        except NoSuchElementException:
            results.append(("Responsive Design", f"{width}x{height}", "Fail", "Login form not found"))

    # Accessibility testing
    axe = Axe(driver)
    axe.inject()
    accessibility_results = axe.run()
    if isinstance(accessibility_results, str):
        accessibility_issues = json.loads(accessibility_results)
    else:
        accessibility_issues = accessibility_results  # It's already a dict

    if len(accessibility_issues['violations']) == 0:
        results.append(("Accessibility", "AXE Core", "Pass", "No accessibility issues found"))
    else:
        for violation in accessibility_issues['violations']:
            results.append(("Accessibility", violation['id'], "Fail", f"{violation['help']} - Impact: {violation['impact']}"))

    driver.quit()
    return results

def analyze_test_results(results):
    df = pd.DataFrame(results, columns=['Type', 'Element', 'Result', 'Details'])
    df['Result'] = df['Result'].map({'Pass': 1, 'Fail': -1})
    
    clf = IsolationForest(contamination=0.1, random_state=42)
    df['Anomaly'] = clf.fit_predict(df[['Result']])
    
    return df

def generate_report(df):
    total_tests = len(df)
    passed_tests = df[df['Result'] == 1]
    failed_tests = df[df['Result'] == -1]
    anomalies = df[df['Anomaly'] == -1]
    
    report = f"""
    Test Report:
    ------------
    Total tests run: {total_tests}
    Tests passed: {len(passed_tests)} ({len(passed_tests)/total_tests*100:.2f}%)
    Tests failed: {len(failed_tests)} ({len(failed_tests)/total_tests*100:.2f}%)
    
    Passed Tests:
    """
    
    for _, row in passed_tests.iterrows():
        report += f"    - {row['Type']}: {row['Element']} ({row['Details']})\n"
    
    report += "\n    Failed Tests:\n"
    
    for _, row in failed_tests.iterrows():
        report += f"    - {row['Type']}: {row['Element']} ({row['Details']})\n"
    
    report += f"""
    Anomalies detected: {len(anomalies)}
    
    Detailed Anomalies:
    """
    
    for _, row in anomalies.iterrows():
        report += f"    - {row['Type']}: {row['Element']} ({row['Details']})\n"
    
    return report

def generate_detailed_report(results):
    report = "Detailed Test Report:\n\n"
    
    # Categorize results
    categories = {}
    for result in results:
        category = result[0]
        if category not in categories:
            categories[category] = []
        categories[category].append(result)
    
    # Generate report for each category
    for category, category_results in categories.items():
        report += f"{category}:\n"
        passed = [r for r in category_results if r[2] == "Pass"]
        failed = [r for r in category_results if r[2] == "Fail"]
        
        report += f"  Passed: {len(passed)}\n"
        report += f"  Failed: {len(failed)}\n"
        
        if failed:
            report += "  Detailed Failures:\n"
            for failure in failed:
                report += f"    - {failure[1]}: {failure[3]}\n"
        
        report += "\n"
    
    return report

if __name__ == "__main__":
    url = "https://ums.paruluniversity.ac.in/Login.aspx"
    links, inputs, buttons = scrape_website(url)
    print(f"Found {len(links)} links, {len(inputs)} input fields, and {len(buttons)} buttons")
    
    results = run_automated_tests(url)
    detailed_report = generate_detailed_report(results)
    print(detailed_report)
