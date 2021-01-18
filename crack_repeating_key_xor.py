

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
    

def repeating_xor_key(cip: bytes, key: bytes) -> bytes:

    repeation = 1 + (len(cip) // len(key))
    key = key * repeation
    key = key[:len(cip)]
    
    msg = bytes([c ^ k for c, k in zip(cip, key)])
    return msg


def break_repeating_xor_key(cipher: bytes) -> bytes:

    
    H_scores_avg = dict()
    
    for key_size in range(2, 20):

        H_scores = []
        H_distances = []

        chunks = [cipher[i:i+key_size] for i in range(0, len(cipher), key_size)]
        # print("*************************************************")
        
        for i in range(0, len(chunks), 2):

        
            try:
                chunk1 = chunks[i]
                chunk2 = chunks[i+1]

                # print(chunk1)
                # print(chunk2)
                
                distance = hamming_distance(chunk1, chunk2)
                H_distances.append(distance)
                
                score = hamming_score(chunk1, chunk2)
                H_scores.append(score)
                
                
            except Exception as e:
                break
        
        # print(H_scores)
        H_scores_avg[str(key_size)] = sum(H_scores) / len(H_scores)
            

    H_scores_avg = {k: v for k, v in sorted(H_scores_avg.items(), key=lambda item: item[1])}
    for key_score in H_scores_avg:
        print(f"{key_score} : {H_scores_avg[key_score]}")
    # print(H_scores_avg)


# repeating_xor_key(b'W;BV;UE*UE=J', b'$^!')
cipher = repeating_xor_key(b'Hello I Am Kourosh and I\'m not secure any more', b'*asd*867t6&*TG')
break_repeating_xor_key(cipher)
