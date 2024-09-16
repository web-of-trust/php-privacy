<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\KekSize;

/**
 * AesKeyWrapper class
 *
 * An implementation of the AES key wrapper based on RFC 3394.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class AesKeyWrapper extends KeyWrapper
{
    /**
     * Constructor
     *
     * @param KekSize $kekSize
     * @return self
     */
    public function __construct(KekSize $kekSize = KekSize::Normal)
    {
        parent::__construct(new \phpseclib3\Crypt\AES('ecb'), $kekSize);
    }
}
