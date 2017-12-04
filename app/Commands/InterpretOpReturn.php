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

class InterpretOpReturn
    extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'script:op-return
                            {--A|asm= : Define an OP RETURN Operation.}
                            {--H|hex= : Define an OP_RETURN Hexadecimal content.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Utility for interpreting Colored Coins OP_RETURN scripts.';

    /**
     * Raw list of command line arguments
     * 
     * @var array
     */
    protected $arguments = [];

    /**
     * Handle command line arguments
     *
     * @return array
     */
    public function setUp(): array
    {
        $our_opts = [
            'asm' => null,
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

        $asmScript = $this->arguments["asm"] ?: "";
        if (empty($asmScript)) {
            $this->error("Please provide a OP_RETURN script with --asm (-c). Example: -c 'OP_RETURN 6f6d6e69000000000000001f000000002faf0800'.");
            return ;
        }

        $this->info("");
        $this->info("Now reading OP_RETURN..");

        $parts = explode(" ", $asmScript);
        if (empty($parts)) {
            $this->error("Malformed OP_RETURN human readable script entered with --asm (-c). Example: -c 'OP_RETURN 6f6d6e69000000000000001f000000002faf0800'.");
            return ;
        }

        $script = strpos($asmScript, "OP_RETURN ") === 0 ? $parts[1] : $parts[0];
        $parsed = $this->parseHex($script);

        $currentPos = 0;
        foreach ($parsed as $title => $data) :

            $this->info("  " . ucfirst($title) . " (Start: " . $currentPos . ". Hexits: " . $data["hexits"] . ")");
            $this->info("");
            $this->warn("    Signed Big Endian:      " . $data["signedBigEndian"]);
            $this->warn("    Signed Litte Endian:    " . $data["signedLittleEndian"]);
            $this->warn("    Unsigned Big Endian:    " . $data["unsignedBigEndian"]);
            $this->warn("    Unsigned Little Endian: " . $data["unsignedLittleEndian"]);
            $this->info("");

            $currentPos += $data["hexits"];
        endforeach ;

        return ;
    }

    protected function parseHex($colorOperation)
    {
        // bufferize
        $scriptHashBuf  = Buffer::hex($colorOperation);

        // split parts of the hexadecimal buffer
        $verBuf  = $scriptHashBuf->slice(0,2);
        $typeBuf = $scriptHashBuf->slice(2,2);
        $propBuf = $scriptHashBuf->slice(4,4);
        $valBuf  = $scriptHashBuf->slice(8,8);

        // ORDER is important!
        $parsed = $this->getInnerData([
            "version" => ["hexits" => 2, "buffer" => $verBuf],
            "transactionType" => ["hexits" => 2, "buffer" => $typeBuf],
            "propertyType"    => ["hexits" => 4, "buffer" => $propBuf],
            "value"           => ["hexits" => 8, "buffer" => $valBuf],
        ]);

        return $parsed;
    }

    protected function getInnerData(array $buffers)
    {
        $convert = new IntegerConvert;
        $response = [];
        foreach ($buffers as $title => $spec) :
            $hexits = (int) $spec["hexits"];
            $buffer = $spec["buffer"];

            // to signed int. (be = Big Endian ; le = Little Endian ; mc = Machine Code)
            $sibe_value = $convert->flip($buffer, $hexits, true, true)->getInt();
            $sile_value = $convert->flip($buffer, $hexits, true, false)->getInt();
            $simc_value = $convert->flip($buffer, $hexits, true, null)->getInt();

            // to unsigned int. (be = Big Endian ; le = Little Endian ; mc = Machine Code)
            $uibe_value = $convert->flip($buffer, $hexits, false, true)->getInt();
            $uile_value = $convert->flip($buffer, $hexits, false, false)->getInt();
            $uimc_value = $convert->flip($buffer, $hexits, false, null)->getInt();

            $response[$title] = [
                "hexits" => $spec["hexits"],
                "buffer" => $spec["buffer"],
                "signedBigEndian"    => $sibe_value,
                "signedLittleEndian" => $sile_value,
                "signedMachineCode"  => $simc_value,
                "unsignedBigEndian"    => $uibe_value,
                "unsignedLittleEndian" => $uile_value,
                "unsignedMachineCode"  => $uimc_value,
            ];
        endforeach ;

        return $response;
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
