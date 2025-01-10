import ipaddress
import re
from urllib.parse import urlparse
import joblib
import os
from django.conf import settings
import numpy as np
import requests

# Path to the model file
MODEL_PATH = os.path.join(settings.BASE_DIR, "models", "isolation_forest_model.pkl")
MODEL_PATH12 = os.path.join(settings.BASE_DIR, "models", "mlp_model.pkl")


# # Function to load the model
def load_model():
    model = joblib.load(MODEL_PATH)
    return model


def load_model1():
    model1 = joblib.load(MODEL_PATH12)
    return model1


# # Function to make predictions
def predict(model, input_data):
    # Perform prediction (assuming the input data is preprocessed properly)
    return model.predict([input_data]).tolist()  # Convert to list if needed


def predict1(model1, features):
    new_data = np.array([features])
    print(features)
    prediction = model1.predict(new_data)
    return prediction[0]


def get_domain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def having_ip(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:  # noqa: E722
        ip = 0
    return ip


def have_at_sign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at


def get_length(url):
    if len(url) < 54:
        length = 0
    else:
        length = 1
    return length


def get_depth(url):
    s = urlparse(url).path.split("/")
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


def redirection(url):
    pos = url.rfind("//")
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


def http_domain(url):
    domain = urlparse(url).netloc
    if "https" in domain:
        return 1
    else:
        return 0


def tiny_url(url):
    shortening_services = (
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
        r"tr\.im|link\.zip\.net"
    )
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


def prefix_suffix(url):
    if "-" in urlparse(url).netloc:
        return 1
    else:
        return 0


def web_traffic(url):
    try:
        querystring = {"domain": url}
        headers = {
            "X-RapidAPI-Key": "cd4733fedbmsh6f2cfc21cf195f2p1d088djsn84e6c824c74e",
            "X-RapidAPI-Host": "similar-web.p.rapidapi.com",
        }
        response = requests.get(
            "https://similar-web.p.rapidapi.com/get-analysis",
            headers=headers,
            params=querystring,
        )
        data = response.json()
        rank = data["GlobalRank"]["Rank"]
        rank = int(rank)
    except (requests.exceptions.RequestException, ValueError, KeyError):
        rank = 1

    if rank < 100000:
        return 1
    else:
        return 0


def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1


def mouse_over(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0


def right_click(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1


def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


def get_http_response(url):
    try:
        response = requests.get(url, timeout=5)  # Set a timeout of 5 seconds
        return response
    except requests.exceptions.RequestException:
        return None


def extract_features(url):
    features = []

    # Address bar based features
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))

    # Domain based features
    dns = 0
    dns_age = 0
    dns_end = 0
    features.append(dns)
    features.append(dns_age)
    features.append(dns_end)
    features.append(web_traffic(url))
    response = get_http_response(url)

    # HTML & Javascript based features
    if response is not None:
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
    else:
        # If response is None, set these features to 0 or None
        features.extend([0, 0, 0, 0])

    return features