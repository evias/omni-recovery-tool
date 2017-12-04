# evias/blockchain-cli 

[![Build Status](https://travis-ci.org/evias/blockchain-cli.svg)](https://travis-ci.org/evias/blockchain-cli)
[![License](https://poser.pugx.org/evias/blockchain-cli/license.svg)](https://packagist.org/packages/evias/blockchain-cli)

The evias/blockchain-cli Package aims to be an easy to use command line interface and API utility Software built around Bitcoin, Colored Coins and NEM blockchain features.

# Dependencies

- php>=7.1 : for laravel-zero/laravel-zero Package
- php7.1-gmp : for Bit-Wasp/bitcoin-php Package
- php7.1-bcmath : for Bit-Wasp/bitcoin-php Package
- php7.1-intl : for UTF-8 encoded passphrases
- php7.1-xml : for PHPUnit
- php7.1-mbstring : for PHPUnit
- php7.1-curl

## Usage Examples

```bash

# Get list of available commands
$ php application list

# Get Simple HD Address from BIP32 Extended Public Key
$ php application wallet:hd-from-xpub --xpub="xpub123456"

# Get Multisig HD Address from BIP32 Extended Public Keys of cosigners
$ php application wallet:hd-from-xpub --xpubs="xpub123456,xpub1234332,xpub493554" --mincount 2

# Get BIP39 Seed from Mnemonic as well as BIP32 Root Key :
$ php application wallet:derive --mnemonic="abandon abandon abandon"

# Get BIP44 Addresses, Public Keys and Private Keys
$ php application wallet:derive --mnemonic="abandon abandon abandon" --path="m/44'/0'/0'/0"

# Get BIP32 Addresses protected by password (Bitcoin Core) :
$ php application wallet:derive --mnemonic="abandon abandon abandon" --password="mySecurePassword" --path="m/0'/0'"

# Create Multisig (P2SH) Colored Coin Transaction
$ php application wallet:p2sh-colored \
            --colored-tx "9141346500a45fb588e2ee2908583d9d2b0484b1941dcb0e50fbf9bf1e4e5b51" \
            --btc-input-tx "4ef5d6c42ceec8d53a896f1bc6b15fa07c52b9f29db0d8e3ce6a4aa5fb9e0ecb" \
            --path="m/44'/0'/0'"  \
            --min 1 --cosig1="this is not the right mnemonic" \
            --cosig2="this one isn't either" \
            --cosig3="and of course, nor is this one" \
            --destination "1PFSCWbPdfQfwtRidBxj5x2HxigG7JGFNb" \
            --change "143f5QPkc5mJurEr2kGPPoecJqkhvaQ2u2" \
            --bitcoin 200000

# Parse a OP_RETURN colored coin hexadecimal payload (Omnilayer or any other OP_RETURN content)
$ php application script:op-return --asm="OP_RETURN 6f6d6e69000000000000001f000000002faf0800 OP_EQUAL"
```

## Pot de vin

If you like the initiative, and for the sake of good mood, I recommend you take a few minutes to Donate a beer or Three [because belgians like that] by sending some Coins (I'm open to any Network :P) to my Wallet:

- NEM/XEM: `NCK34K5LIXL4OMPDLVGPTWPZMGFTDRZQEBRS5Q2S`
- Bitcoin: `38dGUttcaiVg3fTFacMevaWWmC9deuaQc5`
- Ethereum: `0x4C5dda72140A73605dA3E535801a103Be42E99c0`
- Litecoin: `LdoNqbeN9jtMhL1HBicvnoq5RH9eycWQo8`
- IOTA: `PSXGQLYRSSYUPRYPW9VWCMXFUFDMTCUXGYIKJGONXUZEXTYGIJM9MIYCKPYPCEHWQRSX9BKCFQKLYYL9GPFCDFOFJX`

## Credits

- Author: Grégory Saive, [View on Github](https://github.com/evias)

## License

The blockchain-cli Package is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT)
