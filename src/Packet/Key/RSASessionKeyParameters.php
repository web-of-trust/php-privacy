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

use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;

/**
 * RSASessionKeyParameters class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSASessionKeyParameters implements SessionKeyParametersInterface
{
    /**
     * Constructor
     *
     * @param BigInteger $encrypted
     * @return self
     */
    public function __construct(
        private BigInteger $encrypted
    )
    {
    }

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @return RSASessionKeyParameters
     */
    public static function fromBytes(string $bytes): RSASessionKeyParameters
    {
        return new RSASessionKeyParameters(Helper::readMPI($bytes));
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->encrypted->getLength()),
            $this->encrypted->toBytes(),
        ]);
    }

    /**
     * Gets encrypted session key
     *
     * @return BigInteger
     */
    public function getEncrypted(): BigInteger
    {
        return $this->encrypted;
    }
}
