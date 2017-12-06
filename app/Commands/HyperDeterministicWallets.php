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

use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeySequence;
use BitWasp\Bitcoin\Key\Deterministic\MultisigHD;
use BitWasp\Bitcoin\Network\NetworkFactory;

class HyperDeterministicWallets
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:hd-from-xpub
                            {--x|xpub= : Define a Single XPUB (BIP32 Extended Public Key) from which to derive an HD Address.}
                            {--M|xpubs= : Define Multisig XPUBs (BIP32 Extended Public Key) of all co-signers to derive a Multisig HD Address.}
                            {--c|mincount= : Minimum count of cosignatories for a Multisig HD Address.}
                            {--p|path= : Define the derivation path (Example: 0/0 or 0/1 or 0/5). Derivation full path includes the starting XPUB path.}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for creating BIP32 HD Addresses given an input of XPUBs (BIP32 Extended Public Key).';

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
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = ['xpub' => null, 'xpubs' => null, "network" => "bitcoin", "path" => null, 'mincount' => null];
        $options  = array_intersect_key($this->option(), $our_opts);

        if (!empty($options["xpub"]))
            array_push($this->extendedKeys, $options["xpub"]);

        if (!empty($options["xpubs"])) {
            // multisig
            $this->extendedKeys = explode(",", $options["xpubs"]);
        }

        array_walk($this->extendedKeys, function(&$item) { $item = trim($item, " \""); });

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

        // Read Derivation Path and interpret
        $path = $this->arguments["path"];
        $data = [];
        if (empty($path) || ! (bool) preg_match("/^(m\/)?(([0-9]+[h'\/]*)*)/", $path, $data)) {
            $this->error("Invalid Derivation Path provided: " . var_export($path, true));
            return ;
        }

        // clean derivation path (with m/ prefix if provided)
        $path = $data[2];

        $cntXPUBS = count($this->extendedKeys);
        $public   = null;
        $address  = null;
        $script   = null;
        $redeem   = null;
        if (1 === $cntXPUBS) {
            // Simple HD Address from XPUB
            $xpub  = array_shift($this->extendedKeys);
            $key   = HierarchicalKeyFactory::fromExtended($xpub, $network);

            // Path Derivation
            $child = $key->derivePath($path);

            // Read Data
            $public  = $child->getPublicKey();
            $address = $public->getAddress()->getAddress();
        }
        elseif (1 < $cntXPUBS) {
            // Multisig HD Address from multiple XPUBs
            $min = $this->arguments["mincount"] ?: 1;
            $xpubs = [];
            foreach ($this->extendedKeys as $xpub)
                array_push($xpubs, HierarchicalKeyFactory::fromExtended($xpub, $network));

            $seq  = new HierarchicalKeySequence();
            $hdk  = new MultisigHD($min, $path, $xpubs, $seq, true);

            // Read Data
            $address = $hdk->getAddress()->getAddress();
            $script  = $hdk->getScriptPubKey();
            $redeem  = $hdk->getRedeemScript();
        }
        else {
            $this->error("Please provide BIP32 Extended Public Keys using --xpub (Simple HD) or --xpubs (Multisig HD).");
            return ;
        }

        $result = [
            'path' => $path,
            'address' => $address
        ];

        if ($public)
            $result["publicKey"] = $public->getPubKeyHash()->getHex();

        if ($script instanceof \BitWasp\Bitcoin\Script\Script)
            $result["scriptPubKey"] = $script->getScriptParser()->getHumanReadable();

        if ($redeem instanceof \BitWasp\Bitcoin\Script\Script)
            $result["redeemScript"] = $redeem->getScriptParser()->getHumanReadable();

        $this->info("");
        foreach ($result as $field => $value) {

            $prefix = in_array($field, ["path", "address"]) ? "" : PHP_EOL . PHP_EOL . "    ";
            $suffix = in_array($field, ["path", "address"]) ? "" : PHP_EOL;
            $this->info("  " . $field . " : " . $prefix . $value . $suffix);
        }
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
    }

}
