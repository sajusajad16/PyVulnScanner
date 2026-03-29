def log(message):
    print(message)

    with open("report.txt", "a") as f:
        f.write(message + "\n")
