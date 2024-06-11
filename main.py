import requests
import os

def list_files(path: str):
    return [path + "/" + f for f in os.listdir(path)]

if __name__ == "__main__":
    with open("list_benign.csv") as fd:
        fd.readline()
        for i in range(1000):
            x = fd.readline().strip().split(",")
            sha256 = x[0]
            apk_type = x[1]

            list_benign = list_files("benign")
            list_malware = list_files("malware")

            found = False

            for benign in list_benign:
                if sha256 in benign:
                    print(f"found {sha256} in benign, ignore")
                    found = True
                    break
            for malware in list_malware:
                if sha256 in malware:
                    print(f"found {sha256} in malware, ignore")
                    found = True
                    break
            
            if found == True:
                continue

            url = "https://androzoo.uni.lu/api/download"
            params = {
                "apikey": "30d55b20a6dc3b40c4dbbedbd341079798f53973cd16934e60960f43e9bb82f4",
                "sha256": sha256
            }
            print(f"download {sha256}, label: {apk_type}")
            response = requests.get(url, params=params, stream=True)
            if response.status_code == 200:
                # Extract the filename from the Content-Disposition header
                if 'Content-Disposition' in response.headers:
                    filename = response.headers['Content-Disposition'].split('filename=')[-1].strip('"')
                else:
                    # Fallback to a default filename if header is not present
                    filename = 'downloaded_file'
                
                if apk_type == "0":
                    filename = "benign/" + filename
                else:
                    filename = "malware/" + filename

                # Save the file
                with open(filename, 'wb') as f:
                    print(f"save file: {filename}")
                    for chunk in response.iter_content(chunk_size=81920):
                        print("write")
                        f.write(chunk)
                print(f"File downloaded and saved as {filename}")
            else:
                print(f"Failed to download file. Status code: {response.status_code}")
    ...