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

    dist = 0

    for byte1, byte2 in zip(text1, test2):
        dist += bin(byte1 ^ byte2).count('1')

    return dist

def hamming_score(text1: bytes, text2: bytes) -> float:

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
    
    for key_size in range(2, 40):

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
        
        H_scores_avg[str(key_size)] = sum(H_scores) / len(H_scores)
            

    H_scores_avg = {k: v for k, v in sorted(H_scores_avg.items(), key=lambda item: item[1])}

    for key_score in H_scores_avg:
        print(f"{key_score} : {H_scores_avg[key_score]}")


    possible_key_size = int(list(H_scores_avg.keys())[0])
    print(possible_key_size)
    possible_key = b''
    # possible_msg =

    for offset in range(possible_key_size):

        partition = b''
        for index in range(offset, msg_size, possible_key_size):
            partition += bytes([cipher[index]])

        tmp_msg, tmp_key = bruteforce_single_char_xor(partition)
        possible_key += chr(tmp_key).encode()

    possible_msg = repeating_xor_key(cipher, possible_key)
    print(possible_msg)


# repeating_xor_key(b'W;BV;UE*UE=J', b'$^!')
cipher = repeating_xor_key(b'Hello I Am Kourosh and Im not secure anymore', b'f6ffffr65')


# cipher = b",V\x16\x1d\x1d\x106X_AO^~+ \t\t\x02FS\x1a\x1a\x10\x0fI\x1e\x15\x0c\x01\x16UB\x01\x00\x1eB\x12\x14\x0c\x10\x19\x0cM\x02\n\x10\x16H\x14\t\x01MW\x01\x1c\x04\x10\x01\x1c\x1fP\x0e\x00\x00D\x16L.9\x1c1G[\x10CI\t\x15\x0c\x01\nQ\x16L\x0c\x19\x11\x04\x1a\x1dXN\x10\x02\x05\x1dS\x03S\x0b\x1a\x04\x19TS\x18\x0cIcc\x0b\x1f\x1dS\x15T\x10\x18\r\x08CS\x1a\x07C\x1a\x1b\x18\x13\x1b\x1a\x1cO\x11Bhg<y'\x01Y\x1dI\x1a\x19\x03\x1fSC\x07L\x11\x05TS\x1f\x08C\x1aI\x00\x15\x1c\x00\x12F\x07L\x12\x08\x11\x07\x01\x08^\x1d\x04\x04\x04O\x05\x1a@B\t\x08\x0cX\x1f]Iy\x00I\x02\x02\x0b\x16\x01\x01\x16\x03E\x04_\x10\x01\x0cQ\x1d\x0cM\x1f\x1a\x01SR\x07\x0f\x10\x1fX\x07\nE=d\x08\x01\x1cO\x1e\x16R\x11\r\x02\x08BS[\x00^\r\x05\x18\x14\x06\x1d\x14\x01\x16\x04\x00M^\x1d\x16IR\x0b\x05\x02\x07FS\x04H\x0e\x00E\x0fTS\x07\x1bQ\x1d\x04\x04\x04\x1b\x16\x17\x01\x16\x03E\x19Y\x16S(`'I\x1f\x11\x1b\x1b\x16SB\x18\r\x0c_S\x16\x04Q\x07\x05C}e'\x1bDB-5$\x11\x04\x1a\x05\\N\x04\x0c\x1b\nS\x00T\x10\tE\x19Y\x16S\x04U\x1d\x1a\x0c\x17\nS\x1aRB\t\x0b\x0eC\n\x03\x1dU\nI\x1d\x02\x00\x03\x16S\x0e\x15E\x0fT\x15\x1c\x1bUN\x1c\x1d\x1c\x00\x12\x17H\x0c\x0bE\x19^S\x03\x1bU\x18\x0c\x03\x04O\x11\x12EB\x08\x04\x19P~yAD\x06\x08\x19P\x01\x16\x01EB.\t\x08X\x10\x1b\x0c^\x0c\x08\x0e\x18\n\x01SR\x03\x15\x16ME\x1b\x1a\x1a\x10\x07\x1a\x03W\x1bS\x00D\x01\x19\x17\x08\x1dS\x11\x1cDN\x1e\x05\x11\x1bS\x17N\x07\x1fE\x05TS\x18\x07_\x19VD^by*N\x17L\x06\x0c_S\x12\nS\x0b\x1a\x1eP\x1b\x1b\x1aRB-5$\x11\x11\nI`!:9\x19\x01\x14S@\x0cL\x00\x03R\x01\n\x19D\x0b\rM\x1d\n\x00\x00@\x05\tE\x04_S\x07\x01UN\x0f\x02\x02\x02S\x08\x03\x0f\t\x16\x1eP\x14\x16K\nNK\x08\x1e\x0c\x01\nQ\x16\t\x012B\x07\x01\x00^\tK\x10}e\x07\x1c\x01@CGC\x11>\x12\x02UN\x1a\x18\x02\nS\nN\x17L\x01\x02_T\x07IV\x01\x1b\n\x15\x1bS\x07NB\x04\x00\x15\x11\x16\x1d\n_\n\x0cM\x19\x1b]~+of,\x0b\x11\n\x1c\x1c\x10\x00\x0c\x08\x14O\x07\x1c\x01\x11\t\x0b\t\x11\x12\x1d\x10_\x00\x0cM\x11O\x1e\x16R\x11\r\x02\x08\x1dS\x01\x0c]\x0b\x04\x0f\x15\x1dS\x07I\x03\x18E\x08G\x16\x01\x10\x10\x0f\x0e\x08\x1e\x1b\x00T\x01\x12\x19\x07\x01X\x10S\x02U\x17dg\x19\x1cSQf'8H\x0cS\x1f\x16K\x10\x0f\x1aM\x07\n\x1f\x1f\x0fBWL`;~y._\x01\rM\x1c\x1a\x10\x18\x01\r\x19\x11ME\x1b\x16\x1bUcc@P7BC\x11ofhg\x1c^^D\x10,,*9!S d!> 9\x116=*b7995+S>d1?$*tS^D\x1dCdg\x12\x0e\x10J\x12T\x0fW^PJ\x12\x0cRXY\x0f@\x0cBK\x18S\nV\t\x02DFX\x01\rZ\x0b\x12\nJ\x12\x11V[\x04^\x07AF\x0fU^Q\x0e@[BG\x10Z\nQY\x00\x11FPRYY\tH\nJBGS\x0fPXR\x16FZ\x06[\x0c\x0f\x16[\x15\x15\x14\x06[V_WK\x17]R\nY[\x14\x0bGK\x15Q\tT\x08UAD\r\x02W\rT\x11V\x11BE\x04^S^\x04GJ\nVY]XBW\x12J\x11ZXP_P\x11B\x0c\t\x08X\x0e\x13XF\x17B\x01^QZ\x04F\x17X\x01\x08_XDXBG@[\tU\x0c\tJ\x10[V\\\x0f\x0eB_\x10\x10\x16\x07ZQT\x05GD]V\n\x0b\x08@\tCDCR\nW\x0ePJC\x0c\x04Z\x0f\x0cD^F\x17\x15\x07\x0eR\x08UC\x10Q\x04\\\n]\x11[FA\x11W\\P\\W\x17@\x08\x08W[\x0c@by^\x0cOAE(\x7f7S:u-;($O6=b0559t7S$u=:,7*S^\x0cOAhg<y'\x01Y\x1dI\x00\x15\x1c\x00\x12F\x07L\x12\x04]\x1fS\x1aU\x02\x0f@\x14\n\x00\x07S\x17\x0f\x11MX\x1dSX\x00N\x1a\x08\x13\x00\x1d\x17RLBKC\x1f]"
# cipher = open('../KT-B42.msg', 'r').read()
# cipher = bytes.fromhex(cipher)

break_repeating_xor_key(cipher)
