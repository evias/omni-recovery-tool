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
namespace App\Helpers;

use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffer;

class IntegerConvert
{
    public static function flip(BufferInterface $buf, $hexits = 2, $signed = true, $endianness = false)
    {
        $bits = $hexits * 8;
        $method  = ($signed ? "int" : "uInt") . $bits;
        $convert = static::$method($buf->getHex(), $endianness);
        $buffer  = Buffer::int($convert, $hexits)->flip();

        return $buffer;
    }

    public static function int8($i) {
        return is_int($i) ? pack("c", $i) : unpack("c", $i)[1];
    }

    public static function uInt8($i) {
        return is_int($i) ? pack("C", $i) : unpack("C", $i)[1];
    }

    public static function int16($i) {
        return is_int($i) ? pack("s", $i) : unpack("s", $i)[1];
    }

    public static function uInt16($i, $endianness=false) {
        $f = is_int($i) ? "pack" : "unpack";

        if ($endianness === true) {  // big-endian
            $i = $f("n", $i);
        }
        else if ($endianness === false) {  // little-endian
            $i = $f("v", $i);
        }
        else if ($endianness === null) {  // machine byte order
            $i = $f("S", $i);
        }

        return is_array($i) ? $i[1] : $i;
    }

    public static function int32($i) {
        return is_int($i) ? pack("l", $i) : unpack("l", $i)[1];
    }

    public static function uInt32($i, $endianness=false) {
        $f = is_int($i) ? "pack" : "unpack";

        if ($endianness === true) {  // big-endian
            $i = $f("N", $i);
        }
        else if ($endianness === false) {  // little-endian
            $i = $f("V", $i);
        }
        else if ($endianness === null) {  // machine byte order
            $i = $f("L", $i);
        }

        return is_array($i) ? $i[1] : $i;
    }

    public static function int64($i) {
        return is_int($i) ? pack("q", $i) : unpack("q", $i)[1];
    }

    public static function uInt64($i, $endianness=false) {
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
}
