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

class ChildPaysForParent
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:child-pays-for-parent
                            {--m|mnemonic= : Define a Mnemonic for the Wallet to use.}
                            {--p|password= : Define a Password for the Wallet to use (Optional).}
                            {--d|destination= : Define a destination Address for the Rest Bitcoin.}
                            {--I|parent= : Define the Parent transaction ID used for Paying both fees (Child and Parent).}
                            {--i|vindex=0 : Define a Output Index in the Parent transaction ID (linked to --parent transaction ID).}
                            {--P|path= : Define a BIP32 Derivation Path for the HD Key to use for signing the Input.}
                            {--B|bitcoin= : Define a Bitcoin Amount for the transaction in Satoshi (1 Sat = 0.00000001 BTC).}
                            {--f|fee= : Define a TOTAL Bitcoin Fee Amount for the transactions in Satoshi, both Child and Parent should be paid with this Fee. (1 Sat = 0.00000001 BTC).}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for creating Child Pays For Parent transactions.';

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
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = [
            'min' => null,
            'network' => "bitcoin",
            "mnemonic" => null,
            "destination" => null,
            "bitcoin" => null,
            "fee" => null,
            "parent" => null,
            "vindex" => 0,
            "path" => null,
        ];

        // parse command line arguments.
        $options  = array_intersect_key($this->option(), $our_opts);
        $options["mnemonics"] = [$options["mnemonic"]];

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
                $pass = $this->arguments["password"] ?: "";

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

                $path  = $this->arguments["path"] ?: "m/44'/0'/0'/0/0"; // Default is BIP44+BIP32 Derivation Path
                $child = $mnemo32->derivePath($path);
                $public = $child->getPublicKey();

                if (empty($this->cosignerKeysByPath[$path]))
                    $this->cosignerKeysByPath[$path] = [];

                if (empty($this->publicKeysByPath[$path]))
                    $this->publicKeysByPath[$path] = [];

                $this->cosignerKeysByPath[$path][$public->getHex()] = $child;
                array_push($this->publicKeysByPath[$path], $public);

            endforeach ;

            foreach ($this->publicKeysByPath as $path => &$publicKeys) :
                // Sort (by) public keys
                $publicKeys = Buffertools::sort($publicKeys);
                ksort($this->cosignerKeysByPath[$path]);
            endforeach ;

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
        $destination   = $this->arguments["destination"];

        // interpret / validate mandatory parameters
        if (empty($this->arguments["mnemonic"])) {
            $this->error("Please specify a mnemonic with --mnemonic.");
            return ;
        }

        if (empty($this->arguments["parent"])) {
            $this->error("Please specify a Parent transaction id which will be used as Input and will be Spent (using --parent).");
            return ;
        }

        if (empty($destination)) {
            $this->error("Please specify a destination Address with --destination.");
            return ;
        }

        $this->info("");
        $this->info("Now preparing transaction..");

        // address for `destination` (--destination)
        $addressChild = AddressFactory::fromString($destination, $network);

        // this will automatically derive paths to find the right signature
        $this->setUpKeys($this->arguments["mnemonics"], $network);

        // --
        // PREPARE INPUTS
        // --

        // Create Outpoint from --transaction hash.
        $parentInput  = new Outpoint(Buffer::hex($this->arguments["parent"]), $this->arguments["vindex"]);
        $parentScript = ScriptFactory::scriptPubKey()->p2pkh($addressChild->getPubKeyHash());

        // Now construct transaction with built outpoints and outputs.
        $transaction = TransactionFactory::build();
        $txInputs    = [$firstInput];

        // spend --input1
        $transaction = $transaction->spendOutpoint($firstInput);

        // --
        // PREPARE OUTPUTS
        // --

        // prepare transaction fee and amount
        $bitcoin  = (int) $this->arguments["bitcoin"];
        $minerFee = (int) $this->arguments["fee"] ?: 150000; // 0.00150000 BTC default fee (must pay for 2 tx!)

        // create new transaction output
        $txOut = new TransactionOutput($bitcoin - $minerFee, $addressChild->getScriptPubKey()); // leave some BTC for fee with --fee

        // create outputs (order important)
        $transaction = $transaction->outputs([$txOut])->get();

        $this->info("  Before Signing: " . $transaction->getBuffer()->getSize() . " Bytes");
        $this->info("");
        $this->warn("    " . $transaction->getBuffer()->getHex());
        $this->info("");

        // --
        // SIGN TRANSACTION
        // --

        // Sign transaction and display details
        $signed = $this->signTransaction($transaction, [$path => $parentScript]);

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

        // read transaction inputs and create signer
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

            $pub = $this->publicKeysByPath[$path][0];
            $hdk = $this->cosignerKeysByPath[$path][$pub->getHex()];
            $priv = $hdk->getPrivateKey();

            // sign transaction input
            $signer->sign($vin, $priv, $output, $signData, SigHash::ALL);

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
