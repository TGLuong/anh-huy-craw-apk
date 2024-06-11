


if __name__ == "__main__":
    list_malware = []
    list_benign = []
    
    with open("O:/latest.csv/latest.csv") as fd:
        fd.readline()
        for i in range(24000):
            line = fd.readline().split(",")
            sha256 = line[0]
            date = line[3]
            type = line[7]
            if date > "2019-01-01 00:00:00":
                if type == "0":
                    list_benign.append(f"{sha256},{type}\n")
                else:
                    list_malware.append(f"{sha256},{type}\n")

    with open("list_benign.csv", "w") as file:
        file.writelines(list_benign)
    with open("list_malware.csv", "w") as file:
        file.writelines(list_malware)
    ...