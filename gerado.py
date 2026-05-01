import itertools

def generate_passwords():
    base = "senhas123"
    chars = list(base)
    
    # Generate all possible permutations
    perms = list(itertools.permutations(chars))
    
    # Limit to 500 passwords
    passwords = ["".join(p) for p in perms[:500]]
    
    return passwords

if __name__ == "__main__":
    passwords = generate_passwords()
    print(f"Generated {len(passwords)} passwords:")
    for p in passwords:
        print(p)
