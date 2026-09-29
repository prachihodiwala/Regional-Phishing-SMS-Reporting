import re
import unicodedata


def normalize_text(text):
    """
    Basic normalization for Hindi, Gujarati,
    English and Roman-transliterated text.
    """

    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)

    # Convert English letters to lowercase
    text = text.lower()

    # Remove URLs
    text = re.sub(r"https?://\S+|www\.\S+", " ", text)

    # Replace punctuation with spaces
    text = re.sub(r"[^\w\s\u0900-\u097F\u0A80-\u0AFF]", " ", text)

    # Remove extra spaces
    text = re.sub(r"\s+", " ", text)

    return text.strip()




if __name__ == "__main__":

    messages = [
        "YOUR KYC!!! has expired!!!",
        "आपका KYC समाप्त हो गया है!!!",
        "તમારું KYC સમાપ્ત થઈ ગયું છે!!!",
        "Aapka KYC expire ho gaya hai!!!"
    ]

    for message in messages:

        print("Original :", message)
        print("Normalized:", normalize_text(message))
        print("-" * 50)