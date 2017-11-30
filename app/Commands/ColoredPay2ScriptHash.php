<?php
/**
 * Part of the evias/blockchain-cli package.
 *
 * NOTICE OF LICENSE
 *
 * Licensed under the 3-clause BSD License.
 *
 * This source file is subject to the 3-clause BSD License that is
 * bundled with this package in the LICENSE file.
 *
 * @package    evias/blockchain-cli
 * @version    1.0.0
 * @author     Grégory Saive <greg@evias.be>
 * @license    MIT License
 * @copyright  (c) 2017, Grégory Saive
 */
namespace App\Commands;

use Illuminate\Console\Scheduling\Schedule;
use LaravelZero\Framework\Commands\Command;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\Buffertools;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Amount;
use BitWasp\Bitcoin\Base58;
use BitWasp\Bitcoin\Network\Network;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeySequence;
use BitWasp\Bitcoin\Key\Deterministic\MultisigHD;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Transaction\Transaction;
use BitWasp\Bitcoin\Transaction\OutPoint;
use BitWasp\Bitcoin\Transaction\TransactionOutput;
use BitWasp\Bitcoin\Transaction\TransactionFactory;
use BitWasp\Bitcoin\Transaction\Factory\Signer;
use BitWasp\Bitcoin\Transaction\Factory\SignData;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Address\AddressFactory;
use BitWasp\Bitcoin\Script\WitnessScript;
use BitWasp\Bitcoin\Script\P2shScript;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Script;

use App\Helpers\IntegerConvert;

class ColoredPay2ScriptHash
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:p2sh-colored
                            {--m|min=1 : Define number of Minimum Cosignatories for the Multisig P2SH.}
                            {--c1|cosig1= : Define a Mnemonic passphrase for cosignator 1.}
                            {--c1p|cosig1-password= : Define a Password for cosignator 1.}
                            {--c2|cosig2= : Define a Mnemonic passphrase for cosignator 2.}
                            {--c2p|cosig2-password= : Define a Password for cosignator 2.}
                            {--c3|cosig3= : Define a Mnemonic passphrase for cosignator 3.}
                            {--c3p|cosig3-password= : Define a Password for cosignator 3.}
                            {--t|to= : Define a destination Address.}
                            {--O|colored-tx= : Define a Transaction Hash that will be used as the Transaction Output.}
                            {--I|colored-ix=0 : Define a Transaction Input index (Usually named "vout").}
                            {--F|btc-input-tx= : Define a Fee Input Transaction Hash (From where to pay fees).}
                            {--i|btc-input-ix= : Define a Fee Input Transaction index.}
                            {--f|fee= : Define a Fee for the transaction in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--A|amount= : Define the transaction amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--R|raw-amount= : Define the transaction RAW amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--C|currency= : Define a custom currency for the Amount.}
                            {--c|colored-op= : Define a colored Operation (hexadecimal).}
                            {--p|path=m/0 : Define the HD derivation path (BIP32).}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for creating Colored Coins Multisig Pay to Script Hash transactions.';

    /**
     * The current blockchain network instance
     *
     * @var \BitWasp\Bitcoin\Network\Network
     */
    protected $network;

    /**
     * Raw list of command line arguments
     * 
     * @var array
     */
    protected $arguments = [];

    /**
     * List of Public Keys
     *
     * @var array
     */
    protected $publicKeys = [];

    /**
     * List of public key By Hash
     *
     * Those hashes 20-bytes: RIPEMD160(SHA256(hash))
     *
     * @var array
     */
    protected $pubKeyByHash = [];

    /**
     * List of Private Keys by their Public Key
     *
     * @var array
     */
    protected $privateByPub = [];

    /**
     * List of HD Keys
     *
     * @var array
     */
    protected $hdKeysByPub = [];

    /**
     * BIP32 Master Account (m/0)
     *
     * @var array
     */
    protected $masterHD = null;

    /**
     * Array of Smart Properties for Colored Coins
     *
     * @var array
     */
    protected $currencyProps = [
        "USDT" => [
            "currencyId" => 31,
            "currency_str" => "Smart Property",
            "divisibility" => 8,
        ],
    ];

    static protected $strategies = [
        "m/0",
        "m/0/0",
        "m/0'/0'",
        "m/0'/0",
        "m/44'/0'/0'",
        "m/45'/0'/0'",
        "m/48'/0'/0'",
        "m/45'/2147483647/0",
    ];

    /**
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = [
            'min' => null,
            'network' => "bitcoin",
            "cosig1" => null,
            "cosig1-password" => null,
            "cosig2" => null,
            "cosig2-password" => null,
            "cosig3" => null,
            "cosig3-password" => null,
            "to" => null,
            "colored-tx" => null,
            "colored-ix" => 0,
            "fee" => null,
            "amount" => null,
            "currency" => "USDT",
            "raw-amount" => null,
            "colored-op" => null,
            "btc-input-tx" => null,
            "btc-input-ix" => 0,
            "path" => "m/0",
        ];

        // parse command line arguments.
        $options  = array_intersect_key($this->option(), $our_opts);

        // Parse Mnemonics (up to 3)
        $mnemonics = [];
        if ($options["cosig1"]) array_push($mnemonics, $options["cosig1"]);
        if ($options["cosig2"]) array_push($mnemonics, $options["cosig2"]);
        if ($options["cosig3"]) array_push($mnemonics, $options["cosig3"]);

        $options["mnemonics"] = $mnemonics;

        // store arguments
        $this->arguments = $options;
        return $this->arguments;
    }

    /**
     * Load Hyperdeterministic Keys with given --cosig1, --cosig2
     * and --cosig3 arguments. Currently at least one is obligatory.
     *
     * @param   \BitWasp\Bitcoin\Network\Network    $network
     * @return  array
     */
    protected function setUpKeys(array $mnemonics, Network $network): array
    {
        if (empty($this->masterHD)) {
            // create BIP39 Seed for HD Keys, create master backup for Copay (1st signer) 
            // and then derive --path (m/44'/0'/0' is default)

            $bip39Generator = new Bip39SeedGenerator();
            $this->hdKeysByPub = [];
            foreach ($mnemonics as $ix => $mnemonic) {

                // password or empty pass
                $pass = $this->arguments["cosig" . ($ix+1) . "-password"] ?: "";

                // BIP39 seed generation
                $bip39 = $bip39Generator->getSeed($mnemonic, $pass);
                $mnemo32 = HierarchicalKeyFactory::fromEntropy(Buffer::hex($bip39->getHex()));

                if ($ix === 0) {
                    // first cosigner is the wallet creator
                    // XPRV of this account is derived in CoPay!
                    $bip32 = $mnemo32;

                    // Master Backup Key
                    $this->masterHD = $bip32;
                }
                else $bip32 = $this->masterHD;

                // BIP32+BIP44: derive HD Key with derivation path provided through --path (or m/44'/0'/0')
                $path  = $this->arguments["path"] ?: "m/44'/0'/0'";
                $child = $mnemo32->derivePath($path);
                $public = $child->getPublicKey();

                // store HD Key (from which to build keypair)
                $this->hdKeysByPub[$public->getHex()] = $child;
                array_push($this->publicKeys, $public);
            }

            // Sort (by) public keys
            //$this->publicKeys = Buffertools::sort($this->publicKeys);
            //ksort($this->hdKeysByPub);

            $this->info("");
            $this->info("Cosignatories Data Provided: ");
            $this->info("");
            $this->info("  Master Backup XPRV: " . $this->masterHD->toExtendedPrivateKey());
            $this->info("");
            array_map(function($pub, $hd) {
                
                static $ix;
                if (!$ix)
                    $ix = 0;

                $keyHash = $hd->getPublicKey()->getPubKeyHash()->getHex();
                $address = $hd->getPublicKey()->getAddress()->getAddress();
                $xpub    = $hd->toExtendedPublicKey($this->network);
                $xprv    = $hd->toExtendedPrivateKey($this->network);
                
                $this->warn("  " . $ix . ") " . $pub);
                $this->warn("    pubKeyHash: " . $keyHash);
                $this->warn("    address: " . $address);
                $this->warn("    XPUB: " . $xpub);
                $this->warn("    XPRV: " . $xprv);
                $this->info("");

                $ix++;

            }, array_keys($this->hdKeysByPub), array_values($this->hdKeysByPub));
            //}, $this->publicKeys);
        }

        return $this->hdKeysByPub;
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle(): void
    {
        $this->setUp();

        // Read Network and try to initialize
        $net = $this->arguments["network"] ?: "bitcoin";
        try {
            $network = NetworkFactory::$net();
            $this->network = $network;
        }
        catch (Exception $e) {
            $this->error("Invalid Network provided: " . var_export($net, true));
            return ;
        }

        // read parameters..
        $currencySlug  = strtoupper($this->arguments["currency"] ?: "USDT");
        $minCosignatories     = (int) $this->arguments["min"] ?: 1;
        $coloredTransactionId = $this->arguments["colored-tx"];
        $coloredInputIndex    = $this->arguments["colored-ix"];
        $btcTransactionId     = $this->arguments["btc-input-tx"];
        $btcInputIndex        = $this->arguments["btc-input-ix"];

        $destination = $this->arguments["to"];

        // interpret / validate mandatory parameters
        if (empty($this->arguments["mnemonics"])) {
            $this->error("Please specify at least one (max. 3) cosignator mnemonic passphrase with --cosig1, --cosig2 and --cosig3.");
            return ;
        }

        if (empty($coloredTransactionId)) {
            $this->error("Please specify a Transaction Hash with --transaction (32 bytes hexadecimal).");
            return ;
        }

        if (empty($destination)) {
            $this->error("Please specify a destination Address with --to.");
            return ;
        }

        if (! array_key_exists($currencySlug, $this->currencyProps)) {
            $this->error("Provided currency '" . $currencySlug . "' is not present in `currencyProps` (Not supported).");
            return ;
        }

        $this->info("");
        $this->info("Now preparing transaction..");

        $props = $this->currencyProps[$currencySlug];

        // address for `destination` (--to)
        $address = AddressFactory::fromString($destination, $network);

        // Create Outpoint from --transaction hash.
        $coloredInput = new Outpoint(Buffer::hex($coloredTransactionId), $coloredInputIndex);
        $btcInput     = new Outpoint(Buffer::hex($btcTransactionId), $btcInputIndex);

        $cntTrials = 0;
        //do {
            // this will automatically derivat paths to find the right signature
            $this->setUpKeys($this->arguments["mnemonics"], $network);

            // create Multisig redeem script
            // public keys are *NOT SORTED*. Order provided through --keys matters.
            $multisigAddress = new MultisigHD($minCosignatories, $this->arguments["path"], array_values($this->hdKeysByPub), new HierarchicalKeySequence(), true);
            $multisigScript = $multisigAddress->getRedeemScript();
            //$childAddress = $multisigAddress->derivePath($this->argument["path"]);
            
            //$redeemScript   = ScriptFactory::scriptPubKey()->multisig($minCosignatories, $this->publicKeys, false);
            $p2shScript     = $multisigScript;//new P2shScript($redeemScript);
            $outputScript   = $multisigScript->getOutputScript(); //$p2shScript->getOutputScript();

            //$feeMSig   = new MultisigHD($minCosignatories, $this->arguments["path"], array_values($this->hdKeysByPub), new HierarchicalKeySequence(), true);
            //$feeOutput = $feeMSig->getRedeemScript()->getOutputScript();

            // Define coloring operation

            $colorScript = $this->interpretColoredInput();

            // prepare transaction fee and amount
            $fee    = (int) $this->arguments["fee"] ?: 100030; // 0.001.. BTC
            $amount = (int) $this->arguments["raw-amount"] ?: ($this->arguments["amount"] ?: 8) * pow(10, $props["divisibility"]); // 8 USDT

            // create new transaction output
            //$total  = $amount + $fee;
            $txOut  = new TransactionOutput($fee, $outputScript);
            //$txOutCol = new TransactionOutput(0, $outputScript);

            // bundle it together..
            $transaction = TransactionFactory::build()
                                ->spendOutPoint($coloredInput, $outputScript)
                                ->spendOutPoint($btcInput, $outputScript) // Pay BTC Fee
                                ->output($fee, $colorScript->getScript())
                                ->get();

            // Sign transaction and display details
            $signed = $this->signTransaction($transaction, $p2shScript, [$txOut/*, $txOutCol*/]);

            // get human-readable inputs and outputs
            list($inputs,
                $outputs) = $this->formatTransactionContent($transaction);

            $txData = [
                "version" => $transaction->getVersion(),
                "inputs"  => $inputs,
                "outputs" => $outputs
            ];

            //$hmac = str_replace(["OP_HASH160 ", " OP_EQUAL"], "", $inputs[0]);
            //$this->warn("HMAC: " . $hmac);
        //}
        //while (++$cntTrials < 10000 && $hmac != "666e5e7041cd7a9df7075d2f3fc79b6d53df7963");

        //if ($hmac != "666e5e7041cd7a9df7075d2f3fc79b6d53df7963") {
        //    $this->error("Could not derive and sign to the right hash!");
        //    return ;
        //}

        // print details about transaction.
        $this->info("");
        $this->info("  Transaction Data: " . $signed->getBuffer()->getSize() . " Bytes");
        $this->info("");
        $this->warn("    " . $signed->getBuffer()->getHex());
        $this->info("");
        $this->warn(var_export($txData, true));
        $this->info("");
        $this->info("  Transaction ID: ");
        $this->info("");
        $this->warn("    " . $signed->getTxId()->getHex());
        $this->info("");

        // should the transaction be broadcast?
        if (!$this->confirm("Do you wish to Broadcast the transaction now?")) {
            $this->warn("Transaction not broadcast!");
            return ;
        }

        $data = $this->broadcastTransaction($signed);

        $this->info("  Result of Transaction Broadcast: ");
        $this->info("");

        if ($data["success"]) {
            $this->info("SUCCESS!");
            $this->warn(var_export($data, true));
        }
        else {
            $this->error("ERROR Transaction could not be broadcast!");
            $this->warn(var_export($data, true));
        }

        $this->info("");

        return ;
    }

    protected function interpretColoredInput()
    {
        $colorOperation = $this->arguments["colored-op"] ?: "6f6d6e69000000000000001f000000002faf0800";
        $scriptHashBuf  = Buffer::hex($colorOperation);

        $convert = new IntegerConvert;

        $verBuf  = $scriptHashBuf->slice(0,2);
        $typeBuf = $scriptHashBuf->slice(2,2);
        $propBuf = $scriptHashBuf->slice(4,4);
        $valBuf  = $scriptHashBuf->slice(8,8);

        $version = $convert->flip($verBuf, 2, true, true);
        $txType  = $convert->flip($typeBuf, 2, true, true);
        $prop = $convert->flip($propBuf, 4, true, true);
        $value = $convert->flip($valBuf, 8, true, true);

        dd($version, $txType, $prop, $value);

        $hashes  = [$version->getHex(), $txType->getHex(), $prop->getHex(), $value->getHex()];
        $numbers = [$version->getGmp(), $txType->getGmp(), $prop->getGmp(), $value->getGmp()];
        $this->warn("hex: " . implode(" ", $hashes));
        $this->warn("numbers: " . implode(" ", $numbers));
        exit;

        $colorScript    = ScriptFactory::create()->sequence([Opcodes::OP_RETURN, Buffer::hex($colorOperation)]);
    }

    public function uInt64($i, $endianness=false) {
        $f = is_int($i) ? "pack" : "unpack";

        if ($endianness === true) {  // big-endian
            $i = $f("J", $i);
        }
        else if ($endianness === false) {  // little-endian
            $i = $f("P", $i);
        }
        else if ($endianness === null) {  // machine byte order
            $i = $f("Q", $i);
        }

        return is_array($i) ? $i[1] : $i;
    }

    /**
     * Define the command's schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule $schedule
     *
     * @return void
     */
    public function schedule(Schedule $schedule): void
    {
        // $schedule->command(static::class)->everyMinute();
    }

    /**
     * This method will sign the passed transaction with the set of private
     * keys available.
     *
     * Public Keys are SORTED and iterated rather than private keys because
     * the *ordered* public keys list is the actual signing order of the
     * multisignature account.
     *
     * @param   \BitWasp\Bitcoin\Transaction\Transaction    $transaction
     * @param   \BitWasp\Bitcoin\Script\Script              $script
     * @param   array                                       $outputs    Array of TransactionOutput instances
     * @return  \BitWasp\Bitcoin\Transaction\Transaction
     */
    protected function signTransaction(Transaction $transaction, Script $script, array $outputs): Transaction
    {
        $this->info("Now applying Transaction Signatures..");

        $minCosignatories = $this->arguments["min"] ?: 1;
        $ec = \BitWasp\Bitcoin\Bitcoin::getEcAdapter();

        // Multisig - sign transaction with `min` cosignatories
        $signer = (new Signer($transaction, $ec));
        $signData = (new SignData())
                        ->p2sh($script);

        $inputs = [];
        $hashes = array_keys($this->pubKeyByHash);
        for ($ix = 0; $ix < $minCosignatories; $ix++) :

            // Iterate through SORTED PUBLIC KEYS because this defines
            // the signature order for multisignature transactions!
            $pub  = $this->publicKeys[$ix];
            //$priv = $this->privateByPub[$pub->getPubKeyHash()->getHex()];
            $hd = $this->hdKeysByPub[$pub->getHex()];

            if (!$hd->isPrivate()) {
                $this->error("Skipped public key: " . $hd->getPublicKey()->getHex());
                continue;
            }

            // load private key WIF from HD Key
            $priv = $hd->getPrivateKey();

            for ($o = 0, $m = count($outputs); $o < $m; $o++) :
                // sign with current cosigner
                $input  = $signer->input($o, $outputs[$o], $signData);
                $input->sign($priv);

                array_push($inputs, $input);
            endfor;
        endfor;

        // process signatures and mutate transaction
        $signed = $signer->get();
        $overall = true;
        foreach ($inputs as $ix => $input) {
            $result = $input->verify();
            $overall &= $result;

            if ($result)
                $this->info("Validation of Input #" . ($ix + 1) . ": OK");
            else
                $this->warn("Error for Validation of Input #" . ($ix + 1));
        }

        if ($overall)
            $this->info("Transaction Multi-Signed successfully!");

        return $signed;
    }

    /**
     * This method will iterate through the transaction's inputs and
     * outputs and format them for a human readable display.
     *
     * @param   \BitWasp\Bitcoin\Transaction\Transaction    $transaction
     * @return  array
     */
    protected function formatTransactionContent(Transaction $transaction): array
    {
        $inputs = array_map(function($input) { 
            return $input->getScript()->getScriptParser()->getHumanReadable(); 
        }, $transaction->getInputs());

        $outputs = array_map(function($output) { 
            return [
                "value" => $output->getValue(),
                "script" => $output->getScript()->getScriptParser()->getHumanReadable()
            ];
        }, $transaction->getOutputs());

        return [$inputs, $outputs];
    }

    /**
     * This method will broadcast the signed transaction with the
     * Smartbit API from the Sandbox at: https://www.smartbit.com.au/api
     *
     * @see https://www.smartbit.com.au/api
     * @param   \BitWasp\Bitcoin\Transaction\Transaction     $signed
     * @return  mixed
     */
    protected function broadcastTransaction(Transaction $signed)
    {
        // broadcast raw transaction using Smartbit API sandbox
        $params = json_encode(["hex" => $signed->getHex()]);
        $handle = curl_init("https://api.smartbit.com.au/v1/blockchain/pushtx");
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "Content-Type: application/json"
            ],
            CURLOPT_POSTFIELDS => $params
        ]);

        $response = curl_exec($handle);
        if ($response === false) {
            $this->error(curl_error($handle));
            return [];
        }

        $data = json_decode($response, true); // $assoc=true
        return $data;
    }
}
