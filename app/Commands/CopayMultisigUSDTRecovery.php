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
use BitWasp\Bitcoin\Transaction\SignatureHash\SigHashInterface;
use BitWasp\Bitcoin\Transaction\SignatureHash\SigHash;
use BitWasp\Bitcoin\Script\Classifier\OutputClassifier;

use App\Helpers\IntegerConvert;
use RuntimeException;

class CopayMultisigUSDTRecovery
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'omni:copay-recovery
                            {--m|min=1 : Define number of Minimum Cosignatories for the Multisig P2SH.}
                            {--c1|cosig1= : Define a Mnemonic passphrase for cosignator 1.}
                            {--c1p|cosig1-password= : Define a Password for cosignator 1.}
                            {--c2|cosig2= : Define a Mnemonic passphrase for cosignator 2.}
                            {--c2p|cosig2-password= : Define a Password for cosignator 2.}
                            {--c3|cosig3= : Define a Mnemonic passphrase for cosignator 3.}
                            {--c3p|cosig3-password= : Define a Password for cosignator 3.}
                            {--d|destination= : Define a destination Address for the Colored Coins.}
                            {--d2|change= : Define a *Change* destination Address (rest BTC).}
                            {--t1|input1= : Define a Input Transaction Hash #1 (From where to pay fees).}
                            {--i1|vindex1=0 : Define a Input Transaction Index #1.}
                            {--s1|path-sign1= : Define a BIP32 Derivation Path for the HD Key to use for signing Input #1.}
                            {--t2|input2= : Define a Input Transaction Hash #2 (From where to pay fees).}
                            {--i2|vindex2=0 : Define a Input Transaction Index #2.}
                            {--s2|path-sign2= : Define a BIP32 Derivation Path for the HD Key to use for signing Input #2.}
                            {--t3|input3= : Define a Input Transaction Hash #3 (From where to pay fees).}
                            {--i3|vindex3=0 : Define a Input Transaction Index #3.}
                            {--s3|path-sign3= : Define a BIP32 Derivation Path for the HD Key to use for signing Input #3.}
                            {--B|bitcoin= : Define a Bitcoin Amount for the transaction in Satoshi (1 Sat = 0.00000001 BTC).}
                            {--f|fee= : Define a Bitcoin Fee Amount for the transaction in Satoshi (1 Sat = 0.00000001 BTC).}
                            {--D|dust-amount= : Define the dust output amount in Satoshi (Default 5600 Sat - reference amount OMNI) (1 Sat = 0.00000001 BTC).}
                            {--C|currency=USDT : Define a custom currency for the Amount (Default USDT).}
                            {--c|colored-op= : Define a colored Operation (hexadecimal) to include in a OP_RETURN output.}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}
                            {--E|use-elligius : Define wheter to use Elligius Miner PushTx API (non-standard tx accepted).}';

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
    protected $publicKeysByPath = [];

    /**
     * List of Cosigner HD Keys by Derivation Path
     *
     * @var array
     */
    protected $cosignerKeysByPath = [];

    /**
     * List BIP44 Keys by Public Keys
     *
     * @var array
     */
    protected $bip44ByBip39 = [];

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
            "destination" => null,
            "change" => null,
            "bitcoin" => null,
            "fee" => null,
            "dust-amount" => null,
            "currency" => "USDT",
            "colored-op" => null,
            "input1" => null,
            "vindex1" => 0,
            "path-sign1" => 0,
            "input2" => null,
            "vindex2" => 0,
            "path-sign2" => 0,
            "input3" => null,
            "vindex3" => 0,
            "path-sign3" => 0,
            "use-elligius" => false,
        ];

        // parse command line arguments.
        $options  = array_intersect_key($this->option(), $our_opts);

        // Parse Mnemonics (up to 3)
        $mnemonics = [];
        if ($options["cosig1"]) array_push($mnemonics, $options["cosig1"]);
        if ($options["cosig2"]) array_push($mnemonics, $options["cosig2"]);
        if ($options["cosig3"]) array_push($mnemonics, $options["cosig3"]);

        $options["mnemonics"] = $mnemonics;
        $options["use-elligius"] = !empty($options["use-elligius"]);

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
            foreach ($mnemonics as $ix => $mnemonic) :

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

                // BIP44: derive HD Key with derivation path m/44'/0'/0'
                $bip44 = $mnemo32->derivePath("m/44'/0'/0'");
                $this->bip44ByBip39[$bip39->getHex()] = $bip44;

                // derive input-signing keys
                $paths = [
                    0 => $this->arguments["path-sign1"] ?: "m/44'/0'/0'",
                    1 => $this->arguments["path-sign2"] ?: null,
                    2 => $this->arguments["path-sign3"] ?: null,
                ];

                foreach ($paths as $ix => $path) :
                    if (empty($path))
                        continue;

                    $child = $mnemo32->derivePath($path);
                    $public = $child->getPublicKey();

                    if (empty($this->cosignerKeysByPath[$path]))
                        $this->cosignerKeysByPath[$path] = [];

                    if (empty($this->cosignerKeysByPath[$path]))
                        $this->publicKeysByPath[$path] = [];

                    $this->cosignerKeysByPath[$path][$public->getHex()] = $child;
                    array_push($this->publicKeysByPath[$path], $public);
                endforeach ;

            endforeach ;

            //$pubs = array_keys($this->cosignerKeysByPath[$paths[0]]);
            //$this->publicKeysByPath[$paths[0]] = Buffertools::sort($this->publicKeysByPath[$paths[0]]);
            //ksort($this->cosignerKeysByPath[$paths[0]]);

            foreach ($this->publicKeysByPath as $path => &$publicKeys) :
                // Sort (by) public keys
                $publicKeys = Buffertools::sort($publicKeys);
                ksort($this->cosignerKeysByPath[$path]);
            endforeach ;

            //dd(array_keys($this->cosignerKeysByPath[$paths[0]]), array_keys($this->cosignerKeysByPath[$paths[1]]));

            $this->info("");
            $this->info("Cosignatories Data Provided: ");
            $this->info("");
            $this->info("  Master Backup XPRV: " . $this->masterHD->toExtendedPrivateKey());
            $this->info("  Master Backup XPUB: " . $this->masterHD->toExtendedPublicKey());
            $this->info("");

            foreach ($this->cosignerKeysByPath as $path => $cosignersByPub) :
                $this->warn("  1) " . $path);
                array_map(function($pub, $hd) {
                    static $ix;
                    if (!$ix)
                        $ix = 0;

                    $keyHash = $hd->getPublicKey()->getPubKeyHash()->getHex();
                    $address = $hd->getPublicKey()->getAddress()->getAddress();

                    $this->warn("      " . $ix . ") " . $pub);
                    $this->warn("          Address: " . $address);
                    $this->info("");

                    $ix++;

                }, array_keys($cosignersByPub), array_values($cosignersByPub));
            endforeach ;
            //}, $this->publicKeys);
        }

        return $this->cosignerKeysByPath;
    }

    /**
     * Execute the console command.
     *
     * @see https://bitcointalk.org/index.php?topic=2500531.new#new
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

        $destination   = $this->arguments["destination"];
        $changeAddress = $this->arguments["change"] ?: $this->arguments["destination"];

        // interpret / validate mandatory parameters
        if (empty($this->arguments["mnemonics"])) {
            $this->error("Please specify at least one (max. 3) cosignator mnemonic passphrase with --cosig1, --cosig2 and --cosig3.");
            return ;
        }

        if (empty($this->arguments["input1"])) {
            $this->error("Please specify at least one (max. 3) transaction id which will be used for as Input with --input1, --input2 and --input3");
            return ;
        }

        if (empty($destination)) {
            $this->error("Please specify a destination Address with --destination.");
            return ;
        }

        if (! array_key_exists($currencySlug, $this->currencyProps)) {
            $this->error("Provided currency '" . $currencySlug . "' is not present in `currencyProps` (Not supported).");
            return ;
        }

        $this->info("");
        $this->info("Now preparing transaction..");

        $props = $this->currencyProps[$currencySlug];

        // address for `destination` (--destination) and change address `change` (--change)
        $addressColor  = AddressFactory::fromString($destination, $network);
        $addressChange = AddressFactory::fromString($changeAddress, $network);

        // this will automatically derive paths to find the right signature
        $this->setUpKeys($this->arguments["mnemonics"], $network);

        // --
        // PREPARE MULTISIG
        // --

        // create Multisig redeem script
        $m1_path = $this->arguments["path-sign1"] ?: "m/0";
        $m2_path = $this->arguments["path-sign2"] ?: "m/1";
        $m3_path = $this->arguments["path-sign3"] ?: "m/2";

        $m1_Address = new MultisigHD($minCosignatories, $m1_path, array_values($this->cosignerKeysByPath[$m1_path]), new HierarchicalKeySequence(), false);
        $m1_P2SHScript = $m1_Address->getRedeemScript();
        $m1_outputScript = $m1_P2SHScript->getOutputScript();
        $m2_outputScript = null; // default only sign 1 input
        $m3_outputScript = null; // default only sign 1 input

        if ($this->arguments["path-sign2"]) {
            $m2_path = $this->arguments["path-sign2"];
            $m2_Address = new MultisigHD($minCosignatories, $m2_path, array_values($this->cosignerKeysByPath[$m2_path]), new HierarchicalKeySequence(), false);
            //dd($m2_path, $m2_Address->getAddress()->getAddress());
            $m2_P2SHScript = $m2_Address->getRedeemScript();
            $m2_outputScript = $m2_P2SHScript->getOutputScript();
        }

        if ($this->arguments["path-sign3"]) {
            $m3_path = $this->arguments["path-sign3"];
            $m3_Address = new MultisigHD($minCosignatories, $m3_path, array_values($this->cosignerKeysByPath[$m3_path]), new HierarchicalKeySequence(), false);
            $m3_P2SHScript = $m3_Address->getRedeemScript();
            $m3_outputScript = $m3_P2SHScript->getOutputScript();
        }

        // --
        // PREPARE INPUTS
        // --

        // Create Outpoint from --transaction hash.
        $firstInput  = new Outpoint(Buffer::hex($this->arguments["input1"]), $this->arguments["vindex1"]);
        $secondInput = $this->arguments["input2"] ? new Outpoint(Buffer::hex($this->arguments["input2"]), $this->arguments["vindex2"]) : null;
        $thirdInput  = $this->arguments["input3"] ? new Outpoint(Buffer::hex($this->arguments["input3"]), $this->arguments["vindex3"]) : null;

        // Now construct transaction with built outpoints and outputs.
        $transaction = TransactionFactory::build();
        $txInputs    = [$firstInput];

        // spend --input1
        $transaction = $transaction->spendOutpoint($firstInput, $m1_outputScript);

        if ($secondInput) {
            // spend --input2
            array_push($txInputs, $secondInput);
            $transaction = $transaction->spendOutpoint($secondInput, $m2_outputScript);
        }

        if ($thirdInput) {
            // spend --input3
            array_push($txInputs, $secondInput);
            $transaction = $transaction->spendOutpoint($thirdInput, $m3_outputScript);
        }

        // --
        // PREPARE OUTPUTS
        // --

        // Define coloring operation
        $colorScript = $this->getColoredScript();

        // prepare transaction fee and amount
        $bitcoin  = (int) $this->arguments["bitcoin"];
        $dustAmt  = (int) $this->arguments["dust-amount"] ?: 5600; // Omni reference output amount in December 2017
        $minerFee = (int) $this->arguments["fee"] ?: 50000; // 0.00050000 BTC default fee

        // create new transaction output
        //$payToChange = ScriptFactory::scriptPubKey()->payToAddress($addressChange);
        //$payToColor  = ScriptFactory::scriptPubKey()->payToAddress($addressColor);

        $txOut = new TransactionOutput($bitcoin - $minerFee, $addressChange->getScriptPubKey()); // leave some BTC for fee with --fee
        $txOutCol = new TransactionOutput(0, $colorScript); // coloring operation (OP_RETURN xxx)
        $txOutDest = new TransactionOutput($dustAmt, $addressColor->getScriptPubKey()); // dust amount for omni destination

        // create outputs (order important)
        $transaction = $transaction->outputs([$txOutCol, $txOut, $txOutDest]) // order important
                            //->payToAddress($bitcoin - $minerFee, $addressChange) // Change Output must be first + Leave 0.00050000 BTC for Fee
                            //->payToAddress($dustAmt, $addressColor) // Last non-sender output address is Destination of USDT.
                            ->get();

        $this->info("  Before Signing: " . $transaction->getBuffer()->getSize() . " Bytes");
        $this->info("");
        $this->warn("    " . $transaction->getBuffer()->getHex());
        $this->info("");

        // --
        // SIGN TRANSACTION
        // --

        // Sign transaction and display details
        $signed = $this->signTransaction($transaction, [
            $m1_path => ["input" => 0, "script" => $m1_P2SHScript],
            $m2_path => ["input" => 1, "script" => isset($m2_P2SHScript) ? $m2_P2SHScript : null],
            $m3_path => ["input" => 2, "script" => isset($m3_P2SHScript) ? $m3_P2SHScript : null]
        ]);

        // get human-readable inputs and outputs
        list($inputs,
            $outputs) = $this->formatTransactionContent($transaction);

        $txData = [
            "version" => $transaction->getVersion(),
            "inputs"  => $inputs,
            "outputs" => $outputs
        ];

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

    /**
     * This method will return the colored script operation.
     *
     * This should return a sequence of buffers parsed into a Bitcoin script.
     *
     * @return  \BitWasp\Bitcoin\Script\ScriptInterface
     */
    protected function getColoredScript()
    {
        $rawOperation = $this->arguments["colored-op"] ?: "6f6d6e69000000000000001f000000002faf0800";
        $operations   = [
            Opcodes::OP_RETURN,
            Buffer::hex($rawOperation)/*,
            Opcodes::OP_EQUAL*/
        ];

        $colorScript  = ScriptFactory::create()->sequence($operations);
        return $colorScript->getScript();
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
    protected function signTransaction(Transaction $transaction, array $scripts): Transaction
    {
        $this->info("Now applying Transaction Signatures..");

        $minCosignatories = $this->arguments["min"] ?: 1;
        $ec = \BitWasp\Bitcoin\Bitcoin::getEcAdapter();

        // Multisig - sign transaction with `min` cosignatories
        $signer = (new Signer($transaction, $ec));
        $inputs = $transaction->getInputs();

        $outputs = [];
        foreach ($inputs as $idx => $input) :
            $inScript = $input->getScript()->getBuffer()->getHex();
            $output = new TransactionOutput($idx, ScriptFactory::fromHex($inScript));

            array_push($outputs, $output);
        endforeach;

        // --
        // APPLY SIGNATURES
        // --

        // ---
        // DEBUG BITCOIN SCRIPT SOLUTION
        // ---

        //$classifier = new OutputClassifier();
        //$sigVersion = SigHash::V0;
        //$sigChunks = [];
        //$solution = $classifier->decode($outputs[0]->getScript());

        // ASM representation of `$script` bitcoin script
        //$myASM = $script->getScriptParser()->getHumanReadable();

        // ASM representation of the created input
        //$inASM = $outputs[0]->getScript()->getScriptParser()->getHumanReadable();

        // ---
        // END DEBUG BITCOIN SCRIPT SOLUTION
        // ---

        foreach ($scripts as $path => $spec) :

            if ($spec["script"] === null)
                continue; // no script provided for signing

            $vin = $spec["input"];
            $script = $spec["script"];
            $output = $outputs[$vin];

            $signData = (new SignData())->p2sh($script);

            for ($cosig = 0; $cosig < $minCosignatories; $cosig++) :

                $pub = $this->publicKeysByPath[$path][$cosig];
                $hdk = $this->cosignerKeysByPath[$path][$pub->getHex()];
                $priv = $hdk->getPrivateKey();

                $signer->sign($vin, $priv, $output, $signData, SigHash::ALL);
            endfor;

        endforeach ;

        $signed = $signer->get();
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
        $paramKey = "hex";
        $apiUrl   = "https://api.smartbit.com.au/v1/blockchain/pushtx";
        if ($this->arguments["use-elligius"]) {
            $paramKey = "transaction";
            $apiUrl = "http://eligius.st/~wizkid057/newstats/pushtxn.php";
        }

        // broadcast raw transaction
        $params = json_encode([$paramKey => $signed->getHex()]);
        $handle = curl_init($apiUrl);
        
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

        if ($this->arguments["use-elligius"]) {
            // Elligius does not return JSON
            $data = [
                "success" => strpos($response, "Response = 1") !== false,
                "body" => $response,
            ];
            return $data;
        }

        $data = json_decode($response, true); // $assoc=true
        return $data;
    }
}
