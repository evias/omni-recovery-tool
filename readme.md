# evias/omni-recovery-tool 

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

# Parse a OP_RETURN colored coin hexadecimal payload (Omnilayer or any other OP_RETURN content)
$ php application script:op-return --asm="OP_RETURN 6f6d6e69000000000000001f000000002faf0800 OP_EQUAL"
```

## Example of USDT (Omnilayer) recovery on CoPay Multisig Wallet

I have proceeded to a recovery of 8 USDT from a CoPay Multisig Wallet to a Bittrex wallet which you can see in details on the following
links :

- [Bitcoin Network Transaction](https://blockchain.info/tx/09d01daebfb08d9124ba442d8db5e9e11f9cdd29e799d471f7c37768148a4e9a?show_adv=true)
- [Omni Protocol Details](https://www.omniwallet.org/explorer/inspector?view=09d01daebfb08d9124ba442d8db5e9e11f9cdd29e799d471f7c37768148a4e9a)

The created transaction uses 2 Inputs because I needed an address from which I would pay the Bitcoin Fee for processing the transaction. Following
are details about HD Key derivation paths needed **to sign those 2 inputs**. Because both inputs are different Bitcoin Addresses we will need different
public/private key Pairs *for each Input* we need to sign.

In my case, the first input was located in the **third address of the CoPay wallet**. Which turns out to be at derivation path **m/44'/0'/0'/0/2**.

The second input was located in the **first change address of the CoPay wallet**. Which turns out to be at derivation path **m/44'/0'/0'/1/0**.

After gathering the right data about those inputs, I then ran the following command providing --input1 and --input2 are *transaction IDs* of the transaction in which your inputs are the outputs. (Inputs are always Outputs in a previous transaction)

The magic:

```bash
$  php application omni:copay-recovery --input1="9141346500a45fb588e2ee2908583d9d2b0484b1941dcb0e50fbf9bf1e4e5b51" \
                                       --vindex1="1" \
                                       --path-sign1="m/44'/0'/0'/0/2" \
                                       --input2="517a0ad4bf4cc423ce578f043a13e98d405902c08b1bfcac92b199ba3fd2cc39" \
                                       --vindex2="1" \
                                       --path-sign2="m/44'/0'/0'/1/0" \
                                       --cosig1="this is not the right mnemonic" \
                                       --cosig2="nor is this one because crazy" \
                                       --cosig3="this third mnemonic is optional" \
                                       --destination "1Ajqkh2foqMGLRAe9YkS7mwMgsAEiAx3aM" \
                                       --change "143f5QPkc5mJurEr2kGPPoecJqkhvaQ2u2" \
                                       --min 2 \
                                       --bitcoin 75000 \
                                       --fee 40000 \
                                       --colored-op="6f6d6e69000000000000001f000000002faf0800"
```

## How to find the right derivation path

Using your cosigner wallet's mnemonics, it is possible to recover the Copay Multisig Wallet produced at derivation path **X**. For this, I added a command which
will display the Wallet Address as well as the Redeem Script and Output Script in human readable format.

Running this command, you can test a lot of derivation paths **as to find the exact derivation path of the address you need to recover**.

Example derivation paths include:

- CoPay Multisig First Address: **m/44'/0'/0'/0/0**
- CoPay Multisig 19th Address: **m/44'/0'/0'/0/18**
- CoPay Multisig First *Change* Address: **m/44'/0'/0'/1/0**
- CoPay Cosigners Base Derivation Path: **m/44'/0'/0'**.
  - XPUBs of the cosigners are derived with the base derivation path.
- Multibit HD First Address: **m/0'/0/0**.
- BIP44 First Address: **m/44'/0'/0'/0/0**.
- BIP49 First Address: **m/49'/0'/0'/0/0**.
- BIP141 (Segregated Witness) First Address:  **m/0/0**
- Bitcoin Core BIP32 First Address: **m/0'/0'/0'**
  - Always Hardened!
- Blockchain.info BIP32 First Address: **m/44'/0'/0'/0**

The command to create multisig wallets and display their informations such as Address, Redeem Script and Output Script, can be run with the following:

```bash
# Get Multisig Address at derivation m/44'/0'/0'/0/0 (first CoPay Wallet address) with 2 of 3 configuration
php application wallet:multisig --cosig1="this is not the right mnemonic" \
                                --cosig2="nor is this one because crazy" \
                                --cosig3="this third mnemonic is optional" \
                                --count 2 \
                                --path="m/44'/0'/0'/0/0"

# Get Multisig Address at derivation m/44'/0'/0'/0/0 (first CoPay Wallet address) with 1 of 2 configuration
php application wallet:multisig --cosig1="this is not the right mnemonic" \
                                --cosig2="nor is this one because crazy" \
                                --count 1 \
                                --path="m/44'/0'/0'/0/0"

# Get Multisig Address at derivation m/44'/0'/0'/0/1 (second CoPay Wallet address) with 2 of 3 configuration
php application wallet:multisig --cosig1="this is not the right mnemonic" \
                                --cosig2="nor is this one because crazy" \
                                --cosig3="this third mnemonic is optional" \
                                --count 2 \
                                --path="m/44'/0'/0'/0/1"
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
