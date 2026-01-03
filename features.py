import re

def extract_features(url):
   return [
      len(url),                        # long = suspicious
      url.count('.'),                  # many dots
      url.count('-'),                  # dash usage
      url.count('@'),                  # @ symbol
      1 if url.startswith("https") else 0,   # HTTPS?
      1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,  # IP?
      1 if any(x in url.lower() for x in ['login','verify','bank','secure']) else 0
   ]