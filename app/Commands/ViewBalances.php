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
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Base58;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeySequence;
use BitWasp\Bitcoin\Key\Deterministic\MultisigHD;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Address\AddressFactory;
use BitWasp\Bitcoin\Address\AddressInterface;

class ViewBalances
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:read
                            {--m|mnemonic= : (Optional) Define your BIP39 Mnemonic Seed (wordlist).}
                            {--P|password= : (Optional) Define the password for the PBKDF2 (key derivation).}
                            {--p|path= : (Optional) Define the derivation path (Example: 0/0 or 0/1 or 0/5). Derivation full path includes the starting XPUB path.}
                            {--A|address= : Define a wallet address to read.}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for reading Account Balances on the Bitcoin Network.';

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

    protected $omniCurrencies = [
        31 => "USDT",
    ];

    /**
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = ['mnemonic' => null, 'password' => null, 'network' => "bitcoin", "path" => null, "address" => null];
        $options  = array_intersect_key($this->option(), $our_opts);

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
        $net = $this->arguments["network"];
        try {
            $network = NetworkFactory::$net();
        }
        catch (Exception $e) {
            $this->error("Invalid Network provided: " . var_export($net, true));
            return ;
        }

        if (!empty($this->arguments["mnemonic"])) :

            // KEY DERIVATION using mnemonics

            $mn = $this->arguments["mnemonic"];
            $pw = $this->arguments["password"] ?: '';

            if (empty($mn)) {
                $this->error("Cannot create a BIP39 Seed without a mnemonic (-m 'your word list').");
                return ;
            }

            $seed   = new Bip39SeedGenerator();
            $bip39  = $seed->getSeed($mn, $pw);
            $buffer = Buffer::hex($bip39->getHex());

            // Create HD Key from BIP39 Seed
            $bip32 = HierarchicalKeyFactory::fromEntropy($buffer);

            $this->info("");
            $this->info("BIP39 Seed: " . $bip39->getHex());

            $this->printKeyData($bip32, "m/0", $network, function($msg) { $this->warn($msg); });
            //$this->info("BIP32 Root Key: " . $bip32->toExtendedPrivateKey($network));

            // Read Derivation Path and interpret
            $path = $this->arguments["path"];
            $data = [];
            if (empty($path) || ! (bool) preg_match("/^(m\/)?(([0-9]+[h'\/]*)*)/", $path, $data)) {
                // Invalid derivation path or empty path => no derivation done.
                return ;
            }

            // BIP32 DERIVATIONS

            // clean derivation path (with m/ prefix if provided)
            $fullPath = $path;
            $path = $data[2];

            // Prefix m/ removed from `$path`
            $child = $bip32->derivePath($path);

            $this->info("");
            $this->info("BIP32 Derivation Path: " . $this->arguments["path"]);
            $this->info("");

            $this->printKeyData($child, $fullPath, $network, function($msg) { $this->warn($msg); });

            $hex = $child->getPrivateKey()->getHex();
            $wif = $child->getPrivateKey()->toWif($network);

            // Address derivation uses BIP32.
            $cntDerivation = 0;
            for ($d = 0; $d < $cntDerivation; $d++) {
                $nextPath = $fullPath . "/" . $d;
                $this->info("");
                $this->deriveAndPrint($child, $nextPath, $d, $network);
            }

            $address = AddressFactory::fromKey($key->getPublicKey());

        elseif (! empty($this->arguments["address"])) :

            $address = AddressFactory::fromString($this->arguments["address"]);

        endif;

        $result = $this->readAddressOmniProtocol($address);

        if (!isset($result["success"]) || !$result["success"]) {
            $this->error("Error in API Request: " . var_export($result, true));
            return ;
        }

        $totalOf = [];
        foreach ($result["op_returns"] as $opReturnSpec) :

            $txId = $opReturnSpec["txid"];
            $payload = $opReturnSpec["script_hex"];
            $isRecipient = in_array($address->getAddress($network), $opReturnSpec["output_addresses"]);

            $protocol = substr($payload, 4, 8);
            $version  = substr($payload, 12, 4);
            $txType   = substr($payload, 16, 4);
            $property = hexdec(substr($payload, 20, 8));
            $hexAmt   = substr($payload, 28);
            $amount   = hexdec($hexAmt) / 100000000;

            if (!isset($totalOf[$property]))
                $totalOf[$property] = 0;

            if ($isRecipient)
                $totalOf[$property] = $totalOf[$property] + $amount;
            else
                $totalOf[$property] = $totalOf[$property] - $amount;

            if (!array_key_exists($property, $this->omniCurrencies)) {
                $this->error("The amount may be wrong! The Property with ID #" . $property . " is not pre-configured in this Wallet Reader.");
            }

            $this->info(($isRecipient ? "[INCOMING]" : "[OUTGOING]") . " Transaction: " . $txId);
            $this->warn("  AMOUNT: " . $amount . " " . $this->omniCurrencies[$property]);

        endforeach ;

        $this->info("");
        foreach ($totalOf as $property => $total) :

            $this->warn("Current Balance of " . $this->omniCurrencies[$property] . ": " . $total);

        endforeach;

        return ;
    }

    protected function deriveAndPrint(HierarchicalKey $parent, $path, $index = 0, $network = null): void
    {
        $key = $parent->deriveChild($index);
        $this->printKeyData($key, $path, $network, function($msg) { $this->info($msg); });
    }

    protected function printKeyData(HierarchicalKey $key, $path, $network, $logClosure): void
    {
        $data = [];
        preg_match("/^(m\/)?(([0-9]+[h'\/]*)*)/", $path, $data);

        $relativePath = $data[2];
        $absolutePath = $path;

        $levels = explode("/", $relativePath);
        $prefix = array_shift($levels);

        // Address Type differs according to derivation path 
        // m/0  : BIP32 blockchain.info & CoPay Addresses
        // m/0' : BIP32 Bitcoin Core Addresses
        // m/44' : BIP44 Multi Account HD Addresses (purpose 44')
        // m/49' : BIP49 P2WPKH-nested-in-P2SH Addreses
        $type = in_array($prefix, ["0", "0'"]) ? "BIP32" : (
                $prefix == "44'" ? "BIP44" : (
                $prefix == "49'" ? "BIP49" : "ALT"));

        $logClosure("BIP32 " . $absolutePath . " XPRIV: " . $key->toExtendedPrivateKey($network));
        $logClosure("BIP32 " . $absolutePath . " XPUB: " . $key->toExtendedPublicKey($network));

        if ($key->isPrivate()) {
            $hex = $key->getPrivateKey()->getHex();
            $wif = $key->getPrivateKey()->toWif($network);
            $logClosure($type . " " . $absolutePath . " Private Key: " . $hex);
            $logClosure($type . " " . $absolutePath . " Private Key WIF: " . $wif);
        }

        $logClosure($type . " " . $absolutePath . " Public Key: " . $key->getPublicKey()->getHex());
        $logClosure($type . " " . $absolutePath . " Address: " . AddressFactory::fromKey($key->getPublicKey())->getAddress($network));
    }

    protected function readAddressOmniProtocol(AddressInterface $address)
    {
        $paramKey = "hex";
        $apiUrl   = "https://api.smartbit.com.au/v1/blockchain/address/" . $address->getAddress() . "/op-returns";

        // broadcast raw transaction
        $params = json_encode([]);
        $handle = curl_init($apiUrl);
        
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "Content-Type: application/json"
            ],
        ]);

        $response = curl_exec($handle);
        if ($response === false) {
            $this->error(curl_error($handle));
            return [];
        }

        $data = json_decode($response, true); // $assoc=true
        return $data;
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
