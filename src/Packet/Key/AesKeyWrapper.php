<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\KekSize;

/**
 * AesKeyWrapper class
 * An implementation of the AES Key Wrapper from the NIST Key Wrap Specification.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class AesKeyWrapper extends KeyWrapper
{
    /**
     * Constructor
     *
     * @param KekSize $kekSize
     * @return self
     */
    public function __construct(KekSize $kekSize = KekSize::S32)
    {
        parent::__construct(new \phpseclib3\Crypt\AES('ecb'), $kekSize);
    }
}
