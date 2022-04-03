# cloudcutter-bk7231-haxomatic
This is a very work-in-progress tool to automatically find gadget chains for [this smart device exploit](https://rb9.nl/posts/2022-03-29-light-jailbreaking-exploiting-tuya-iot-devices/). It's meant to eventually be a semi-automatic method of building profiles for [tuya-cloudcutter](https://github.com/khalednassar/tuya-cloudcutter).

Very experimental, might not work if at all for the particular app code blob and currently just prints offsets.

## Usage
Pipenv is used for package management, so ensure that it is installed and run `pipenv install` to install the dependencies. 

Afterwards, you can invoke `pipenv run python haxomatic.py <decrypted app code file>`
