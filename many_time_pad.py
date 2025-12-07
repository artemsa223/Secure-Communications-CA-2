import binascii
from collections import defaultdict, Counter

# Ciphertext data from the PDF
hex_ciphertexts = [
    "0f381a39fe6f41bd57c44646eacc3ecb2b695ae729ee174ac650ab0c92547a73b19ca7a24d40162bea9c0d1c2c1395678f6dec2ae8b4eaa449b1511507c3e06dd6c9c02c69c5eca4241d3f3585f44440ad011078381bacc075e4c3",
    "0f351c71d96e59b742c34053a6853d9930664da237f24456874ae61198546b7ea6c8f7a34b581823ead8490c29568e618b68a929f3e6e6ea0ca35f1944c2ec70d686df3028c4f9a42a0720748cbb4e41a74c07773213bad56eefde922d44cdbcbf3e008be80870a5eb7c55ab907f18fcf347dd433bcf83432d0849e80c22b0",
    "127d183cb07342a042d40553e9cc3dd83d2e5cea3be91756cf46f904d74f6c3fbcd3b8f04f431c27af8842003147c27a9425b82fe2e6f8ed5fb2540e05c9ee23d681cc3d28c7f6e227522466c2fe555aa34f116d7b1fb58168f4d8d72c0dd3b3bb701197fe087baefe784eac9c3002b4f9488f0029c08606341d49ef113ff7cdd8c60abe6f5cefbff792e9317e4f9d36b948dfddf409e264580f65",
    "0f351c71e76f5fbe548d4c54a69a2bcb3d2e4ceb3cfb5250c24dff419949683f8ed3a5f04f57116fe797410d2c138b60db6da534a7abe0f658b65b5c0ccbeb67d1c9d9216d8befeb35173f3596f40d4fa84e1e702818fbc06bec90d4315fceacfa7112c3e55d74aaf3394bb08f7504a8e5019c4e3e838e0f364946f31721a49ad2d24ff6775efcb4f79fe4217a01b43cb5068bf3b52ca76543187274",
    "1a311571ff660da658c80545e98325ca646746a22ef55202d04cf90d93067c70a6c8b6b94c161120af95421b3a138b609d6abe2ae6b2e6eb42f7431405c4a56ad1c9cf3b67cafbe72301393583e80d58a34517767b19b58166a0c3db304acfbafa721591ea4d398af07c49b69a7118fcff4889597aca81433b4953f50b2bbbdf9dcd0aff7013d3b5a3d3ec2b73019c3aa91b8bddf411a72b480c636cc6597494151386",
    "1835183ce0614abc558d4c41a69521cc646f5ae77aee5247cc4ae506d752777ae8c8a5a5565e5f26fcd84f0c2b47877cdb71a426e9e6eea440be525c00cff166c19dc23b28e2eba4271c2e7a97e94c49af5252787b1dbacf27f4df923c4883baa26e158dfe416faebd7c4dba973004b9ff4a914529d0cf1432004cf94520bedf9dd00aea6750e9b5a580ad266d44de3cb304d295f447a1634c117a68c41e67d50d09c35928a62e6d6648371b40ac83b274cecb04d6c41b6fba",
    "1928103df46943b510d94044ee8227da256208f123ee4347ca50ab0899507073bed9a4f04343161320fbd8420f7f5b837c9f25bb28f5adafe542b3170f14cfe66ac385c4336dcfbfef2c1d3a7987ff4a4bea4d13773c05bac662f390d3304983afa871008cee4775b8bd7a54bb907e11fcfd4f99003ec68d163d0e49f2026ca3dfcec006f06513fcb4b3d3ff2279409d27b21ac2dbf2",
    "12290a71f96d5dbd43de4c45ea896ecd2b2e45ed2cf81756c803e70881433f6ba79cb8a047441e3bead84c1d7f528c77db69a931e2aaaff345a35f1311dea56fc788db2066ccbff030132e7091bb4f47be52526a3e15b6c869e7dccb7e40c6beb4771a84e14d6ab8bd7f49be9e7d13b2e852dd4f3c839f06281a4ff20420f7d3d3d200ec6f52e9b3b89d",
    "14331c71fd614eba59c34007e58d2099206108f632f81755c851e04198403f79a1daa3a902590d2be6964c1b26138f6b95258228a7abeee744be591944c9e46d828dc2697cc3faa4351d3f7ec2f44b0ea54f17393e08afd366efc2d63743c2ada33e1982e3",
    "127d0c22f5640da65f8d514fef822599306649f67afe4e40c251f81196457a3fbfdda4f0445f193bf6d8540c3e41912e9a72ad3ea791e7e558f77e5c10c2ea76c581d9697fcaeca4241b2b619bbb544bab5301393a07bad827f7d1c17e42cdb3a33e0086e30860aefc6b48ff986717a5bc6093447ad487022e4969bc1124b8cfdadc1bbe7552eefaa396e36766449f21ae48cac2f41ee262595d616cd95963990b03824934ea2a287844722140b583a2638bcf16c3df0323a212740f3d5b517fbd10e4e253512e",
    "0c385930e2650da658c80544ee8522dd366b46a235fb17438757ee029f487073a7dbbeb3435a5f2ee89d0d3e3a138a6f8d60ec21e8b3e1e00ca4430e01cbe86fcb87c82d28dcfefd31522273c2ff4247a44652742e13b38168e690dd2b5f83adb56b008ae34d39bcf26b50ffa9621fb2e84893477aca9c43340600f00a22b0dfcf941bf66713f2b4bb8aad307e58de3cbb48d9d0e515ad6f581e7f63cd59609a160d900d1faf2329634f354814b793bc37c3d700d5c71271e30d740e7815516dbd1af8a344533fcb",
    "0829003df52058a155c90553e9cc2cdc646f46a233f34347d542e8159e49713faad9a3a74753116ffb90484937468f6f9525bf28f2aaafe542b317080bc5e970829dc5287c8be8e130176d798bf6445aa34f1539121efbd56fe590d6374acaabbb725486ff4939a2e9394cb6957c56b4fd5798002ecccf00350445bc033eb8d79dc007fb2240f2afbbd3ec2b704f9b",
    "0f351c71c7654ff251de056ea68920cf2d7d49e53ff9174bd303fc04d74e7e69ad9cb9bf56160c2aea960d002b139b6b8f25982fe2e6e9f158a2451944c3f623d19dc425648beceb621f38768abb4f47ad46176b7b04b3c069a0c4da3b0dd3bea96a54b7e4453989f86b55ba8b635b90f944"
]

# Convert hex to bytes
ciphertexts = [binascii.unhexlify(h) for h in hex_ciphertexts]
num_messages = len(ciphertexts)
max_length = max(len(ct) for ct in ciphertexts)

# Known plaintext fragments based on partial recovery
KNOWN_CRIBS = {
    # Message 1
    (0, 0): "Technological progress has merely provided us with more efficient means for going backwards",
    # Message 2
    (1,
     0): "The Internet is the most important single development in the history of human communication since the invention of ",
    (1, 115): "call waiting",
    # Message 3
    (2,
     0): "I am sorry to say that there is too much point to the wisecrack that life is extinct on other planets because their scientists were more advanced than ours",
    # Message 4
    (3,
     0): "The world is very different now For man holds in his mortal hands the power to abolish all forms of human poverty and all forms of human life",
    (3, 143): "John F Kennedy",
    # Message 5
    (4,
     0): "All of the books in the world contain no more information than is broadcast as video on a single large American city in a single year Not all bits have equal value",
    # Message 6
    (5,
     0): "Champagne if you are seeking the truth is better than a lie detector It encourages a man to be expansive even reckless while lie detectors are only a challenge to tell lies successfully",
    # Message 7
    (6, 0): "Building technical systems involves ",
    # Message 8
    (7,
     0): "Its impossible to move to live to operate at any level without leaving traces bits seemingly meaningless fragments of personal information",
    # Message 9
    (8, 0): "One machine can do the work of fifty ordinary men No machine can do the work of one extraordinary man",
    # Message 10
    (9,
     0): "I used to think that cyberspace was fifty years away What I thought was fifty years away was only ten years away and what I thought was ten years away it was already here I just wasnt aware of it yet",
    # Message 11
    (10,
     0): "We are the children of a technological age We have found streamlined ways of doing much of our routine work Printing is no longer the only way of reproducing books",
    # Message 12
    (11,
     0): "Style used to be an interaction between the human soul and tools that were limiting In the digital era it will have to come from the soul alone",
    # Message 13 - The target message
    (12,
     0): "The Web as I envisaged it we have not seen it yet The future is still so much bigger than the past Tim Berners-Lee"
}


class ManyTimePadSolver:
    def __init__(self, ciphertexts):
        self.ciphertexts = ciphertexts
        self.num_messages = len(ciphertexts)
        self.max_length = max(len(ct) for ct in ciphertexts)
        self.keystream = [None] * self.max_length
        self.confidence_scores = [defaultdict(float) for _ in range(self.max_length)]

    def xor_bytes(self, a, b):
        """XOR two byte sequences"""
        return bytes(x ^ y for x, y in zip(a, b))

    def is_printable_ascii(self, byte):
        """Check if a byte represents printable ASCII"""
        return 32 <= byte <= 126

    def score_plaintext(self, text):
        """Score a plaintext fragment based on character distribution"""
        if not text:
            return 0

        score = 0
        text_lower = text.lower()

        # Character type scoring
        for char in text:
            if char.isalpha():
                score += 2.0
            elif char == ' ':
                score += 1.5
            elif char in '.,!?;:\'"':
                score += 0.5
            elif char.isdigit():
                score += 0.3
            elif not self.is_printable_ascii(ord(char)):
                score -= 5.0

        # Common word bonuses
        common_words = [' the ', ' and ', ' to ', ' of ', ' a ', ' in ', ' is ', ' it ',
                        ' for ', ' with ', ' on ', ' at ', ' by ', ' from ', ' that ']
        for word in common_words:
            if word in text_lower:
                score += 5.0 * text_lower.count(word)

        # Technical terms bonus (based on recovered content)
        tech_terms = ['internet', 'technology', 'cyberspace', 'digital', 'web',
                      'machine', 'computer', 'system', 'information']
        for term in tech_terms:
            if term in text_lower:
                score += 8.0

        return score

    def apply_known_cribs(self):
        """Apply known plaintext cribs to recover keystream bytes"""
        print("Applying known cribs to recover keystream...")

        for (msg_idx, pos), plaintext in KNOWN_CRIBS.items():
            if msg_idx >= self.num_messages:
                continue

            plaintext_bytes = plaintext.encode('ascii', errors='ignore')
            ciphertext = self.ciphertexts[msg_idx]

            # Derive keystream from known plaintext
            for i in range(min(len(plaintext_bytes), len(ciphertext) - pos)):
                if pos + i < len(ciphertext):
                    key_byte = ciphertext[pos + i] ^ plaintext_bytes[i]
                    self.confidence_scores[pos + i][key_byte] += 100.0  # High confidence

    def statistical_analysis(self):
        """Use statistical properties to identify likely spaces"""
        print("Performing statistical analysis for space detection...")

        # XOR all ciphertext pairs
        for i in range(self.num_messages):
            for j in range(i + 1, self.num_messages):
                ct1, ct2 = self.ciphertexts[i], self.ciphertexts[j]
                min_len = min(len(ct1), len(ct2))

                for pos in range(min_len):
                    xor_result = ct1[pos] ^ ct2[pos]

                    # If XOR results in a letter, one might be space
                    if (65 <= xor_result <= 90) or (97 <= xor_result <= 122):
                        # Hypothesis: ct1[pos] is space
                        key_candidate1 = ct1[pos] ^ ord(' ')
                        self.confidence_scores[pos][key_candidate1] += 1.0

                        # Hypothesis: ct2[pos] is space
                        key_candidate2 = ct2[pos] ^ ord(' ')
                        self.confidence_scores[pos][key_candidate2] += 1.0

    def iterative_crib_dragging(self):
        """Try common English phrases at different positions"""
        print("Performing crib dragging with common phrases...")

        common_cribs = [
            "The ", " the ", " and ", " to ", " of ", " is ", " in ", " for ",
            " with ", " that ", " this ", " from ", " are ", " was ", " has ",
            "technology", "internet", "computer", "digital", "information",
            "Tim Berners-Lee", "John F Kennedy"
        ]

        for crib in common_cribs:
            crib_bytes = crib.encode('ascii')

            for msg_idx in range(self.num_messages):
                ct = self.ciphertexts[msg_idx]

                for pos in range(len(ct) - len(crib_bytes) + 1):
                    # Derive potential keystream
                    potential_key = bytes(ct[pos + i] ^ crib_bytes[i]
                                          for i in range(len(crib_bytes)))

                    # Test this keystream against all messages
                    total_score = 0
                    valid_count = 0

                    for test_idx in range(self.num_messages):
                        test_ct = self.ciphertexts[test_idx]
                        if pos + len(crib_bytes) <= len(test_ct):
                            decrypted = ''.join(chr(test_ct[pos + i] ^ potential_key[i])
                                                if self.is_printable_ascii(test_ct[pos + i] ^ potential_key[i])
                                                else '?'
                                                for i in range(len(crib_bytes)))

                            if '?' not in decrypted:
                                score = self.score_plaintext(decrypted)
                                if score > 0:
                                    total_score += score
                                    valid_count += 1

                    # If this looks promising, add to confidence scores
                    if valid_count >= self.num_messages * 0.6 and total_score > 20:
                        for i in range(len(potential_key)):
                            self.confidence_scores[pos + i][potential_key[i]] += total_score / 10

    def finalize_keystream(self):
        """Select the most confident keystream bytes"""
        print("Finalizing keystream selection...")

        for pos in range(self.max_length):
            if not self.confidence_scores[pos]:
                continue

            # Get the byte with highest confidence
            candidates = sorted(self.confidence_scores[pos].items(),
                                key=lambda x: x[1], reverse=True)

            if candidates:
                best_byte, best_score = candidates[0]

                # Accept if confidence is high enough
                if best_score >= 10.0:
                    if len(candidates) > 1:
                        second_score = candidates[1][1]
                        # Require significant margin over second best
                        if best_score > second_score * 1.5:
                            self.keystream[pos] = best_byte
                    else:
                        self.keystream[pos] = best_byte

    def decrypt_all_messages(self):
        """Decrypt all messages using the recovered keystream"""
        decrypted = []

        for i, ct in enumerate(self.ciphertexts):
            plaintext = []
            for j in range(len(ct)):
                if j < len(self.keystream) and self.keystream[j] is not None:
                    pt_byte = ct[j] ^ self.keystream[j]
                    if self.is_printable_ascii(pt_byte):
                        plaintext.append(chr(pt_byte))
                    else:
                        plaintext.append('.')
                else:
                    plaintext.append('?')
            decrypted.append(''.join(plaintext))

        return decrypted

    def solve(self):
        """Main solving routine"""
        print("=" * 80)
        print("Many-Time Pad Attack Solver")
        print("=" * 80)

        # Step 1: Apply known cribs
        self.apply_known_cribs()

        # Step 2: Statistical analysis
        self.statistical_analysis()

        # Step 3: Crib dragging
        self.iterative_crib_dragging()

        # Step 4: Finalize keystream
        self.finalize_keystream()

        # Step 5: Decrypt messages
        decrypted = self.decrypt_all_messages()

        # Calculate statistics
        recovered_bytes = sum(1 for b in self.keystream if b is not None)
        print(f"\nKeystream recovery: {recovered_bytes}/{self.max_length} bytes "
              f"({100 * recovered_bytes / self.max_length:.1f}%)")

        return decrypted


# Main execution
if __name__ == "__main__":
    solver = ManyTimePadSolver(ciphertexts)
    decrypted_messages = solver.solve()

    # Save results to file
    print("\n" + "=" * 80)
    print("RECOVERED PLAINTEXTS")
    print("=" * 80)

    with open('final_recovered_plaintexts.txt', 'w', encoding='utf-8') as f:
        for i, plaintext in enumerate(decrypted_messages, 1):
            output = f"Message {i}:\n{plaintext}\n"
            print(output)
            f.write(output + "\n")

    # Save partial keystream
    with open('recovered_keystream.bin', 'wb') as f:
        keystream_bytes = bytes([b if b is not None else 0 for b in solver.keystream])
        f.write(keystream_bytes)

    print("\n" + "=" * 80)
    print("TARGET MESSAGE (Message 13):")
    print("=" * 80)
    print(decrypted_messages[12])
    print("\nFiles saved: final_recovered_plaintexts.txt, recovered_keystream.bin")
