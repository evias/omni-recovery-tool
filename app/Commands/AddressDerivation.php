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
use BitWasp\Bitcoin\Network\Network;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeySequence;
use BitWasp\Bitcoin\Key\Deterministic\MultisigHD;
use BitWasp\Bitcoin\Network\NetworkFactory;

use App\Helpers\IntegerConvert;
use RuntimeException;

class AddressDerivation
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wallet:multisig
                            {--c|count=1 : Define number of Minimum Cosignatories for the Multisig P2SH (with --multisig).}
                            {--c1|cosig1= : Define a Mnemonic passphrase for cosignator 1.}
                            {--c1p|cosig1-password= : Define a Password for cosignator 1.}
                            {--c2|cosig2= : Define a Mnemonic passphrase for cosignator 2.}
                            {--c2p|cosig2-password= : Define a Password for cosignator 2.}
                            {--c3|cosig3= : Define a Mnemonic passphrase for cosignator 3.}
                            {--c3p|cosig3-password= : Define a Password for cosignator 3.}
                            {--p|path= : Define a Derivation Path for the derived Address.}
                            {--N|network=bitcoin : Define which Network must be used ("bitcoin" for Bitcoin Livenet).}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for creating Address out of multi-mnemonics (Multisig) or single mnemonics and with specifying a Derivation Path.';

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
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = [
            'count' => null,
            'network' => "bitcoin",
            "cosig1" => null,
            "cosig1-password" => null,
            "cosig2" => null,
            "cosig2-password" => null,
            "cosig3" => null,
            "cosig3-password" => null,
            "path" => "",
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

        // this will automatically derive paths to find the right address
        $this->setUpKeys($this->arguments["mnemonics"], $network);

        // read parameters..
        $minCosignatories = (int) $this->arguments["count"] ?: 1;
        $derivationPath   = $this->arguments["path"];
        $cosignerHDKeys   = array_values($this->cosignerKeysByPath[$derivationPath]);

        // interpret / validate mandatory parameters
        if (empty($this->arguments["mnemonics"])) {
            $this->error("Please specify at least one (max. 3) cosignator mnemonic passphrase with --cosig1, --cosig2 and --cosig3.");
            return ;
        }

        // now create address
        $address = new MultisigHD($minCosignatories, $derivationPath, $cosignerHDKeys, new HierarchicalKeySequence(), false); // sort=false because already sorted.
        $p2shScript = $address->getRedeemScript();
        $outScript  = $p2shScript->getOutputScript();

        $this->info("");
        $this->info("  Derivation Path: " . $derivationPath);
        $this->info("  Configuration:   " . $minCosignatories . " of " . count($cosignerHDKeys));
        $this->info("  Address: " . $address->getAddress()->getAddress());
        $this->info("  Redeem Script: ");
        $this->info("");
        $this->warn("    " . $p2shScript->getScriptParser()->getHumanReadable());
        $this->info("");
        $this->info("  Output Script: ");
        $this->info("");
        $this->warn("    " . $outScript->getScriptParser()->getHumanReadable());
        $this->info("");

        return ;
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

                $path  = $this->arguments["path"] ?: "m/44'/0'/0'/0/0"; // Default is BIP44 first address
                $child = $mnemo32->derivePath($path);
                $public = $child->getPublicKey();

                if (empty($this->cosignerKeysByPath[$path]))
                    $this->cosignerKeysByPath[$path] = [];

                if (empty($this->cosignerKeysByPath[$path]))
                    $this->publicKeysByPath[$path] = [];

                $this->cosignerKeysByPath[$path][$public->getHex()] = $child;
                array_push($this->publicKeysByPath[$path], $public);

            endforeach ;

            // Sort (by) public keys
            foreach ($this->publicKeysByPath as $path => &$publicKeys) :
                $publicKeys = Buffertools::sort($publicKeys);
                ksort($this->cosignerKeysByPath[$path]);
            endforeach ;
/*
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

*/
        }

        return $this->cosignerKeysByPath;
    }
}
