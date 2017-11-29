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

class MultisigPay2ScriptHash
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:p2sh-multisig
                            {--m|min=1 : Define number of Minimum Cosignatories for the Multisig P2SH.}
                            {--K|keys= : Define a comma-separated list of Private Keys WIFs.}
                            {--t|to= : Define a destination Address.}
                            {--O|transaction= : Define a Transaction Hash that will be used as the Transaction Input.}
                            {--I|input=0 : Define a Transaction Input index (Usually named "vout").}
                            {--f|fee= : Define a Fee for the transaction in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--A|amount= : Define the transaction amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
                            {--R|raw-amount= : Define the transaction RAW amount without fee in Satoshi (0.00000001 BTC = 1 Sat).}
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
     * List of Public Keys
     *
     * @var array
     */
    protected $publicKeys = [];

    /**
     * List of Private Keys by their Public Key
     *
     * @var array
     */
    protected $privateByPub = [];

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
            "keys" => null,
            "to" => null,
            "transaction" => null,
            "fee" => null,
            "amount" => null,
            "raw-amount" => null,
            "index" => 0,
        ];

        // parse command line arguments.
        $options  = array_intersect_key($this->option(), $our_opts);

        // Parse WIF (Wallet Import Format) Private Keys
        $wifs = explode(",", $options["keys"]);
        $privKeys = [];
        $publicKeys = [];
        $privByPub = [];
        foreach ($wifs as $wif) {

            $priv = PrivateKeyFactory::fromWif($wif);
            array_push($privKeys, $priv);
            array_push($publicKeys, $priv->getPublicKey());

            $privByPub[$priv->getPubKeyHash()->getHex()] = $priv;
        }

        // Sort public keys
        $this->publicKeys = Buffertools::sort($publicKeys);
        $this->privateByPub = $privByPub;

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

        $min  = (int) $this->arguments["min"] ?: 1;
        $txid = $this->arguments["transaction"];
        $vout = $this->arguments["input"] ?: 0;
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

        $this->info("Now preparing transaction..");

        // address for `destination` (--to)
        $address = AddressFactory::fromString($dest, $network);

        // Create Outpoint from --transaction hash.
        $outpoint = new Outpoint(Buffer::hex($txid), $vout);

        // Script is P2SH | P2WSH | P2PKH
        $redeemScript   = ScriptFactory::scriptPubKey()->multisig($min, $this->publicKeys, true); //sort=true
        $p2shScript     = new P2shScript($redeemScript);
        $outputScript   = $p2shScript->getOutputScript();

        // prepare transaction fee and amount
        $fee    = (int) $this->arguments["fee"] ?: 100030; // 0.001.. BTC
        $amount = (int) $this->arguments["raw-amount"] ?: ($this->arguments["amount"] ?: 8) * pow(10, 8); // 8 USDT

        // create new transaction output
        //$total  = $amount + $fee;
        $txOut  = new TransactionOutput($amount, $outputScript);

        // bundle it together..
        $transaction = TransactionFactory::build()
                            ->spendOutPoint($outpoint, $outputScript)
                            ->output($amount + $fee, $outputScript)
                            ->get();


        // Sign transaction and display details
        $signed = $this->signTransaction($transaction, $p2shScript, [$txOut]);

        // get human-readable inputs and outputs
        list($inputs,
             $outputs) = $this->formatTransactionContent($transaction);

        $txData = [
            "version" => $transaction->getVersion(),
            "inputs"  => $inputs,
            "outputs" => $outputs
        ];

        // print details about transaction
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
    protected function signTransaction(Transaction $transation, Script $script, array $outputs): Transaction
    {
        $this->info("Now applying Transaction Signatures..");

        $minCosignatories = $this->arguments["min"] ?: 1;
        $ec = \BitWasp\Bitcoin\Bitcoin::getEcAdapter();

        // Multisig - sign transaction with `min` cosignatories
        $signer = (new Signer($transaction, $ec));
        $signData = (new SignData())
                        ->p2sh($script);

        $inputs = [];
        for ($ix = 0; $ix < $min; $ix++) :

            // Iterate through SORTED PUBLIC KEYS because this defines
            // the signature order for multisignature transactions!
            $pub  = $this->publicKeys[$ix];
            $priv = $this->privateByPub[$pub->getPubKeyHash()->getHex()];

            for ($o = 0, $m = count($outputs); $o < $m; $o++) :
                // sign with current cosigner
                $input  = $signer->input(0, $outputs[$o], $signData);
                $input->sign($priv);

                array_push($inputs, $input);
            endfor;
        endfor;

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
