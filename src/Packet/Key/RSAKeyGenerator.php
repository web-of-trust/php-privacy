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

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\RSA;
use OpenPGP\Enum\RSAKeySize;

/**
 * RSA key generator class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSAKeyGenerator implements KeyGeneratorInterface
{
    /**
     * Constructor
     *
     * @param RSAKeySize $keySize
     * @return self
     */
    public function __construct(
        private RSAKeySize $keySize
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function generate(): PrivateKey
    {
        return RSA::createKey($this->keySize->value);
    }
}
