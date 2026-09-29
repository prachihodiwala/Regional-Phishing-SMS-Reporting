from datasketch import MinHash


def create_minhash(text, num_perm=128):
    """
    Creates a MinHash fingerprint for the given text.
    """

    minhash = MinHash(num_perm=num_perm)

    # Create 3-word shingles
    words = text.split()

    if len(words) < 3:
        shingles = [" ".join(words)]
    else:
        shingles = [
            " ".join(words[i:i + 3])
            for i in range(len(words) - 2)
        ]

    for shingle in shingles:
        minhash.update(shingle.encode("utf-8"))

    return minhash


def calculate_similarity(text1, text2):
    """
    Calculates approximate Jaccard similarity
    using MinHash.
    """

    minhash1 = create_minhash(text1)
    minhash2 = create_minhash(text2)

    return minhash1.jaccard(minhash2)


if __name__ == "__main__":

    sms1 = "your kyc has expired please update your account"

    sms2 = "your kyc has expired please update your account immediately"

    sms3 = "congratulations you won a lottery prize"

    print("SMS 1 vs SMS 2:")
    print(calculate_similarity(sms1, sms2))

    print()

    print("SMS 1 vs SMS 3:")
    print(calculate_similarity(sms1, sms3))