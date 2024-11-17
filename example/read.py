from funsecret import read_secret

read_secret("baidu", "secret", "accessToken", value="this is accessToken")
read_secret("baidu", "secret", "refreshToken", value="this is refreshToken")

print(read_secret("baidu", "secret", "accessToken"))
print(read_secret("baidu", "secret", "refreshToken"))
