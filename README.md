# Mnemonic Shamir Secret Sharing Tool

This tool provides an implementation of Shamir's Secret Sharing for [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonics. It splits a 24-word BIP-39 mnemonic into _n_ BIP-39 mnemonic, a.k.a. shares, such that _t_ shares are sufficient and required to recover the original mnemonic.

_This tool is functionally similar to [SLIP39](https://slip39.com/) but is not compatible with the method._

## Disclaimer

**This tool has been not audited and may not work correctly under all deployment scenarios. Use at your own risk!**

This tool is meant to be used by trusted operators. Malicious inputs to the tool are not considered in the threat model. It is also assumed that this tool will be used in a physically secure environment. The threat model does not consider shoulder surfing, eavesdropping, TEMPEST, and other side-channel attacks.

## Dependencies

* Ubuntu 20.04+
* OpenSSL `crypto` [library](https://www.openssl.org/docs/man1.0.2/man3/crypto.html), in particular, its `bn` and `sha256` functions. To install it, run:

```
sudo apt-get install libssl-dev
```

## Building

```
cd MnemonicShamirCLI;
make
```

## Usage

Use the tool to split a BIP-39 mnemonic into _n_ shares, recoverable with a subset of _t_ shares, where 2 <= _n_ <= 20 and 2 <= _t_ <= _n_.

### Generating a New Mnemonic (for testing)

_This feature is meant for generating seed phrases for testing purposes only. High value operational seed phrases should be generated on secure hardware with good sources of entropy and/or a validated implementation of a pseudo-random number generator._

To generate a valid BIP-39 mnemonic, run:

```
./build/mnemonic-sss generate
```

Generated mnemonic will be displayed on a new line below:

```
./build/mnemonic-sss generate

Generated mnemonic:

world lawn observe spray wish kit auction focus bone view opera artefact ice mimic expand valve upgrade hour dilemma virtual bread member midnight predict
```

### Splitting the Mnemonic

To split a BIP-39 mnemonic into _n_ shares with _t_ recovery threshold, run:

```
./build/mnemonic-sss split -quorum <threshold t> -total <total num of shares n>
```

The default input method accepts the short form of the mnemonic words that consist of the first four characters of each mnemonic word.
To use the full mnemonic words instead, use the option `-word long`. Accepted parameters are `short` or `long`:

```
./build/mnemonic-sss split -quorum <threshold t> -total <total num of shares n> -word <short/long>
```

The default input mode is by word. That is, it is required to enter each word in separate lines. To input the full phrase in one line, use the option `-mode phrase`. Accepted parameters are `word` or `phrase`:

```
./build/mnemonic-sss split -quorum <threshold t> -total <total num of shares n> -word <short/long> -mode <word/phrase>
```

When prompted, enter a valid BIP-39 mnemonic to be split into _n_ shares. Afterwards, the tool will output _n_ shares with their share numbers. To recover the original mnemonic, at least _t_ shares **together** with their correct share numbers will be required:

```
./build/mnemonic-sss split -quorum 3 -total 4 -word long

Please enter each word of the 24 word mnemonic phrase. Press return key after each word.
1: world
2: lawn
3: observe
4: spray
5: wish
6: kit
7: auction
8: focus
9: bone
10: view
11: opera
12: artefact
13: ice
14: mimic
15: expand
16: valve
17: upgrade
18: hour
19: dilemma
20: virtual
21: bread
22: member
23: midnight
24: predict

Testing all combinations of shares...
Tested 30%
Tested 60%
Tested 100%
Tested 130%
Tested 4 combinations.
Tested all combinations of 3 shares out of 4.

Record and store these 4 shares along with their corresponding share numbers in a safe place.
You will need 3 shares to recover the original mnemonic phrase.

1: suggest make purse ethics deliver vivid clutch below olympic keep fetch leisure jealous park law round glue debris mouse sauce attack print uncover top
2: pride prevent minor tattoo fruit afraid vacuum tube brass employ caught shell decade timber lemon ghost magnet method riot cry title earn cradle unknown
3: income true cruel lumber guess power forest super orbit genuine anger task rebuild fame fiber they feel hat ritual few occur foam found razor
4: country drop pig dose fire tobacco hobby token broken seed acoustic situate travel valley zone deer spare spatial music calm copy truck hidden cement
```

After the splitting operation, the program will try all the combinations of the shares to recover the original secret. The progress of the computation and the total number of tests will be displayed.

**Note that it is vitally important that you record the share number (1, 2, 3 and 4 in the example above) along with each share. You will need this information in order to successfully recover the original mnemonic.**

### Recovering the Original Mnemonic

To recover a BIP-39 mnemonic from _t_ shares, run:

```
./build/mnemonic-sss recover -quorum <threshold t>
```

The default input method accepts the short form of the mnemonic words that consist of the first four characters of each mnemonic word.
To use the full mnemonic words instead, use the option `-word long`. Accepted parameters are `short` or `long`:

```
./build/mnemonic-sss recover -quorum <threshold t> -word <short/long>
```

The default input mode is by word. That is, it is required to enter each word in separate lines. To input the full phrase in one line, use the option `-mode phrase`. Accepted parameters are `word` or `phrase`:

```
./build/mnemonic-sss recover -quorum <threshold t> -word <short/long> -mode <word/phrase>
```

When prompted for share number, enter the share number, e.g. 1. Then, when prompted for the mnemonic, enter the 24 word mnemonic corresponding to that share number. Repeat the process _t_ times. Upon completion, received shares will be used to recover the original mnemonic:

```
./build/mnemonic-sss recover -quorum 3

Please enter your secret share mnemonic phrases, a share number followed by 24 word phrase:

Please enter share number (share 1 of 3):
2
Please enter the first 4 characters of each word of the 24 word mnemonic phrase. Press return key after each word.
(share 1 of 3)
1: prid
2: prev
3: mino
4: tatt
5: frui
6: afra
7: vacu
8: tube
9: bras
10: empl
11: caug
12: shel
13: deca
14: timb
15: lemo
16: ghos
17: magn
18: meth
19: riot
20: cry
21: titl
22: earn
23: crad
24: unkn

Please enter share number (share 2 of 3):
4
Please enter the first 4 characters of each word of the 24 word mnemonic phrase. Press return key after each word.
(share 2 of 3)
1: coun
2: drop
3: pig
4: dose
5: fire
6: toba
7: hobb
8: toke
9: brok
10: seed
11: acou
12: situ
13: trav
14: vall
15: zone
16: deer
17: spar
18: spat
19: musi
20: calm
21: copy
22: truc
23: hidd
24: ceme

Please enter share number (share 3 of 3):
1
Please enter the first 4 characters of each word of the 24 word mnemonic phrase. Press return key after each word.
(share 3 of 3)
1: sugg
2: make
3: purs
4: ethi
5: deli
6: vivi
7: clut
8: belo
9: olym
10: keep
11: fetc
12: leis
13: jeal
14: park
15: law
16: roun
17: glue
18: debr
19: mous
20: sauc
21: atta
22: prin
23: unco
24: top

Recovered mnemonic phrase is:
world lawn observe spray wish kit auction focus bone view opera artefact ice mimic expand valve upgrade hour dilemma virtual bread member midnight predict
```

### Build and run in Docker

Start the docker daemon and navigate to this directory, then
- build the Docker image once
```sh
docker build -t msss .
```
- start an interactive container
```sh
docker run -it --rm msss
```
- run your commands as documented above, e.g.
```sh
./mnemonic-sss generate
```
