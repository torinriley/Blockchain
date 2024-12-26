from src.sha256 import SHA256

class DemoSHA256:

    def demo_hash_empty_string(self):
        sha256 = SHA256()
        result = sha256.hash("")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        print(f"Hashing empty string: {result == expected}")

    def demo_hash_abc(self):
        sha256 = SHA256()
        result = sha256.hash("abc")
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        print(f"Hashing 'abc': {result == expected}")

if __name__ == "__main__":
    demo = DemoSHA256()
    demo.demo_hash_empty_string()
    demo.demo_hash_abc()
