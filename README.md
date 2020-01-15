# pw-test
This is a little tool to compare a password and the hash generated by the `pw` utility from [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth).

## Build
You can build pw-test locally and run, or alternatively, you can run the utility via a temporary golang Docker container:
```
sudo docker run --rm -it --name test golang /bin/bash
```

Build the pw-test utility:
```
mkdir ~/pw
cd ~/pw
git clone https://github.com/iegomez/pw-test.git .
go build
```
Once completed you should find a `pw-test` binary.

## Usage
Test password hashes:
```
Usage of ./pw-test:
  -h string
    	pbkdf2 password hash. use single quotes so $ symbols aren't taken as variables
  -p string
    	plain text password
  -s staring
      salt encoding, defaults to 'base64'
```
