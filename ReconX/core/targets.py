def load_targets(file_path):
    targets = []

    try:
        with open(file_path, "r") as f:
            for line in f:
                t = line.strip()
                if t:
                    targets.append(t)
    except:
        print("[-] Failed to load targets file")

    return targets
