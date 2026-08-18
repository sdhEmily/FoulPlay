<p align="center">
  <img src="Resources/icon-readme.png" width="128" alt="FoulPlay">
</p>
<h1 align="center">FoulPlay</h1>
<h3 align="center">A platform-agnostic IPA decryptor for iOS 15+</h3>
<h6 align="center">(Tested with tvOS and iOS apps)</h6>

### Requirements
- Jailbroken iOS device running iOS 15 or above (Tested on iOS 15.0, 16.2, 17.7 and 18.7)
- License for the IPA you want to decrypt
- Target app IPA with an arm64 Mach-O binary

### How to use
1. Download and install the latest deb from [here](https://github.com/sdhEmily/FoulPlay/releases)
2. Open FoulPlay and select the IPA you want to decrypt
3. Use the share sheet to export the decrypted IPA


### Building
This requires [Theos](https://theos.dev) to be installed and in PATH and [Xcode](https://developer.apple.com/xcode/) with the iOS development tools
```sh
git clone https://github.com/sdhEmily/FoulPlay
cd FoulPlay
make package
```

### Thanks
[Lakr233/unfair](https://github.com/Lakr233/unfair) - IPA decryption method  
[@mineek](https://github.com/mineek) - Being swag ‼️  
Claude - Helped me learn and assisted in development
