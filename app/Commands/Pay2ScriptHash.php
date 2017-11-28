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
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeySequence;
use BitWasp\Bitcoin\Key\Deterministic\MultisigHD;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
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

class Pay2ScriptHash
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:p2sh-color
                            {--m|min=1 : Define number of Minimum Cosignatories for the Multisig P2SH.}
                            {--K|keys= : Define a comma-separated list of Private Keys WIFs.}
                            {--t|to= : Define a destination Address.}
                            {--O|transaction= : Define a Transaction Hash that will be used as the Transaction Output.}
                            {--F|fee-input= : Define a Fee Input Transaction Hash (From where to pay fees).}
                            {--f|fee= : Define a Fee for the transaction in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--A|amount= : Define the transaction amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--R|raw-amount= : Define the transaction RAW amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--C|currency= : Define a custom currency for the Amount.}
                            {--c|colored-op= : Define a colored Operation (hexadecimal).}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for creating Multisig Pay to Script Hash transactions.';

    /**
     * The IoC Container
     * 
     * @var \Illuminate\Container\Container
     */
    protected $app;

    /**
     * Raw list of command line arguments
     * 
     * @var array
     */
    protected $arguments = [];

    /**
     * List of XPUB input
     * 
     * @var array
     */
    protected $extendedKeys = [];

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

    /**
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp()
    {
        $our_opts = [
            'min' => null,
            'network' => "bitcoin",
            "keys" => null,
            "to" => null,
            "transaction" => null,
            "fee" => null,
            "amount" => null,
            "currency" => "USDT",
            "raw-amount" => null,
            "colored-op" => null,
            "fee-input" => null,
        ];

        // parse command line arguments.
        $options  = array_intersect_key($this->option(), $our_opts);

        // store arguments
        $this->arguments = $options;
        return $this->arguments;
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
        }
        catch (Exception $e) {
            $this->error("Invalid Network provided: " . var_export($net, true));
            return ;
        }

        $cur  = strtoupper($this->arguments["currency"] ?: "USDT");
        $min  = (int) $this->arguments["min"] ?: 1;
        $txid = $this->arguments["transaction"];
        $txfee= $this->arguments["fee-input"];
        $dest = $this->arguments["to"];
        $keys = $this->arguments["keys"] ?: "";
        $wifs = explode(",", $keys);

        if (empty($wifs)) {
            $this->error("Please specify a comma-separated list of Private Key WIFs with --keys.");
            return ;
        }

        if (empty($txid)) {
            $this->error("Please specify a Transaction Hash with --transaction (32 bytes hexadecimal).");
            return ;
        }

        if (empty($dest)) {
            $this->error("Please specify a destination Address with --dest.");
            return ;
        }

        if (! array_key_exists($cur, $this->currencyProps)) {
            $this->error("Provided currency '" . $cur . "' is not present in `currencyProps`.");
            return ;
        }

        $this->info("Now preparing transaction..");

        $props = $this->currencyProps[$cur];
        $address = AddressFactory::fromString($dest, $network);

        // Parse WIF (Wallet Import Format) Private Keys
        $privKeys = [];
        $publicKeys = [];
        $privByPub = [];
        foreach ($wifs as $wif) {

            $priv = PrivateKeyFactory::fromWif($wif);
            array_push($privKeys, $priv);
            array_push($publicKeys, $priv->getPublicKey());

            $privByPub[$priv->getPublicKey()->getHex()] = $priv;
        }

        // Sort public keys
        //$publicKeys = Buffertools::sort($publicKeys);

        // Create Outpoint from --transaction hash.
        $outpoint = new Outpoint(Buffer::hex($txid), 1);
        $outpointFee = new Outpoint(Buffer::hex($txfee), 0);

        // Script is P2SH | P2WSH | P2PKH
        $redeemScript   = ScriptFactory::scriptPubKey()->multisig($min, $publicKeys, false);
        $p2shScript     = new P2shScript($redeemScript);
        $outputScript   = $p2shScript->getOutputScript();

        $colorRedeem    = ScriptFactory::scriptPubKey()->multisig($min, $publicKeys, false);
        $colorP2SH      = new P2shScript($colorRedeem);
        $colorOutput    = $colorP2SH->getOutputScript();

        // Define coloring operation
        $colorOperation = $this->arguments["colored-op"] ?: "6f6d6e69000000000000001f000000002faf0800";
        $colorScript    = ScriptFactory::create()->sequence([
                            Opcodes::OP_RETURN, Buffer::hex($colorOperation)]);

        // prepare transaction fee and amount
        $fee    = (int) $this->arguments["fee"] ?: 100030; // 0.001.. BTC
        $amount = (int) $this->arguments["raw-amount"] ?: ($this->arguments["amount"] ?: 8) * pow(10, $props["divisibility"]); // 8 USDT

        // create new transaction output
        //$total  = $amount + $fee;
        $txOut  = new TransactionOutput($fee, $outputScript);
        $txOutCol = new TransactionOutput(0, $colorOutput);

        // bundle it together..
        $transaction = TransactionFactory::build()
                            ->spendOutPoint($outpoint, $outputScript)
                            ->spendOutPoint($outpointFee, $colorOutput)
                            ->output(0, $colorScript->getScript())
                            ->output($fee, $outputScript)
                            ->get();

        $this->info("Now applying Transaction Signatures..");
    
        $ec = \BitWasp\Bitcoin\Bitcoin::getEcAdapter();

        // Multisig - sign transaction with `min` cosignatories
        $signer = (new Signer($transaction, $ec));
        $signData = (new SignData())
                        ->p2sh($p2shScript);

        $inputs = [];
        for ($ix = 0; $ix < $min; $ix++) :

            // Iterate through SORTED PUBLIC KEYS because this defines
            // the signature order for multisignature transactions!
            $pub  = $publicKeys[$ix];
            $priv = $privByPub[$pub->getHex()];

            // sign with current cosigner
            $input1  = $signer->input(0, $txOut, $signData);
            $input1->sign($priv);

            array_push($inputs, $input1);

            $input2  = $signer->input(0, $txOutCol, $signData);
            $input2->sign($priv);

            array_push($inputs, $input2);
        endfor;

        // process signatures and mutate transaction
        $signed = $signer->get();

        foreach ($inputs as $ix => $input) {
            $result = $input->verify();

            if ($result)
                $this->info("Validation of Input #" . ($ix + 1) . ": OK");
            else
                $this->warn("Error for Validation of Input #" . ($ix + 1));
        }

        $inputs = array_map(function($input) { 
            return $input->getScript()->getScriptParser()->getHumanReadable(); 
        }, $transaction->getInputs());

        $outputs = array_map(function($output) { 
            return [
                "value" => $output->getValue(),
                "script" => $output->getScript()->getScriptParser()->getHumanReadable()
            ];
        }, $transaction->getOutputs());

        $txData = [
            "version" => $transaction->getVersion(),
            "inputs"  => $inputs,
            "outputs" => $outputs
        ];
        $this->info("Transaction Multi-Signed successfully!");

        // Job done.
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

        if (!$this->confirm("Do you wish to Broadcast the transaction now?")) {
            $this->warn("Transaction not broadcast!");
            return ;
        }

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
            return ;
        }

        $data = json_decode($response, true); // $assoc=true

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
}
