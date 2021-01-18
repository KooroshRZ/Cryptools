from collections import Counter

def compute_fitting_quotient(text: bytes) -> float:

    """

    Given the stream of bytes `text` the function computes the fitting
    quotient of the letter frequency distribution for `text` with the
    letter frequency distribution of the English language.

    The function returns the average of the absolute difference between the
    frequencies (in percentage) of letters in `text` and the corresponding
    letter in the English Language.

    """

    occurance_english = {
        'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
        'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
        'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
        'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
        'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
        'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
        'y': 1.9913847,    'z': 0.0746517
    }

    dist_english = list(occurance_english.values())

    counter = Counter(text)
    dist_text = [
        (counter.get(ord(ch), 0) * 100) / len(text)
        for ch in occurance_english
    ]

    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

def hamming_distance(text1: bytes, test2: bytes) -> int:

    """
    Gives two texts and returns us the hamming distance between them
    """

    dist = 0
    for byte1, byte2 in zip(text1, test2):
        dist += bin(byte1 ^ byte2).count('1')

    return dist

def hamming_score(text1: bytes, text2: bytes) -> float:

    """
    Gives two texts and returns us the hamming score between them
    It's actually normalized of hamming distance
    """

    size1 = len(text1)
    size2 = len(text2)

    min_size = min(size1, size2)

    return hamming_distance(text1, text2) / (min_size * 8)
    
def single_byte_xor(text: bytes, key: int) -> bytes:

    """
    Given a plain text `text` as bytes and an encryption key `key` as a byte
    in range [0, 256) the function encrypts the text by performing
    XOR of all the bytes and the `key` and returns the resultant.
    """

    return bytes([b ^ key for b in text])


def repeating_xor_key(cip: bytes, key: bytes) -> bytes:

    """
    Function for repeating key xor encryption and decryption
    """

    repeation = 1 + (len(cip) // len(key))
    key = key * repeation
    key = key[:len(cip)]
    
    msg = bytes([c ^ k for c, k in zip(cip, key)])
    return msg


def bruteforce_single_char_xor(cipher_text: bytes):

    """
    The function deciphers an encrypted text using Single Byte XOR and returns
    the original plain text message and the encryption key.
    """

    original_text, encryption_key, min_fq = None, None, None
    for k in range(256):
        # we generate the plain text using encryption key `k`
        _text = single_byte_xor(cipher_text, k)
        
        # we compute the fitting quotient for this decrypted plain text
        _fq = compute_fitting_quotient(_text)
        
        # if the fitting quotient of this generated plain text is lesser
        # than the minimum seen till now `min_fq` we update.
        if min_fq is None or _fq < min_fq:
            encryption_key, original_text, min_fq = k, _text, _fq

    # return the text and key that has the minimum fitting quotient
    return original_text, encryption_key


def break_repeating_xor_key(cipher: bytes) -> bytes:

    msg_size = len(cipher)
    H_scores_avg = dict()
    
    for key_size in range(2, 100):

        H_scores = []
        H_distances = []

        chunks = [cipher[i:i+key_size] for i in range(0, len(cipher), key_size)]
        
        for i in range(0, len(chunks), 1):

        
            try:
                chunk1 = chunks[i]
                chunk2 = chunks[i+1]

                distance = hamming_distance(chunk1, chunk2)
                H_distances.append(distance)
                
                score = hamming_score(chunk1, chunk2)
                H_scores.append(score)
                
            except Exception as e:
                break
        
        try:
            H_scores_avg[str(key_size)] = sum(H_scores) / len(H_scores)
        except Exception as e:
            print("[!] An error occured, Maybe reached key size limit for this message length")
            print(e)
            break
            

    H_scores_avg = {k: v for k, v in sorted(H_scores_avg.items(), key=lambda item: item[1])}


    possible_key_sizes = list(H_scores_avg.keys())[0:10]
    possible_keys = dict()
    english_scores = dict()

    for possible_size in possible_key_sizes:

        possible_size = int(possible_size)
        possible_key = b''

        for offset in range(possible_size):

            partition = b''
            for index in range(offset, msg_size, possible_size):
                partition += bytes([cipher[index]])

            tmp_msg, tmp_key = bruteforce_single_char_xor(partition)
            possible_key += chr(tmp_key).encode()

        possible_msg = repeating_xor_key(cipher, possible_key)
        E_score = compute_fitting_quotient(possible_msg)
        english_scores[E_score] = possible_msg
        possible_keys[E_score] = possible_key

    min_score = min(english_scores.keys())
    main_message = english_scores[min_score]
    print(f"[+] Extracted Key : {possible_keys[min_score]}")
    print(f"[+] Extracted Msg : \n{main_message}")


message = open('./message.txt', 'rb').read()
cipher = repeating_xor_key(message, b'asd8tT^&STD')


# cipher = open('../KT-B42.msg', 'r').read()
# cipher = bytes.fromhex(cipher)

break_repeating_xor_key(cipher)
