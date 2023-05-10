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
 * ElGamalSessionKeyParameters class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalSessionKeyParameters implements SessionKeyParametersInterface
{
    /**
     * Constructor
     *
     * @param BigInteger $gamma
     * @param BigInteger $phi
     * @return self
     */
    public function __construct(
        private BigInteger $gamma,
        private BigInteger $phi
    )
    {
    }

    /**
     * Reads encrypted session key parameters from bytes
     *
     * @param string $bytes
     * @return ElGamalSessionKeyParameters
     */
    public static function fromBytes(string $bytes): ElGamalSessionKeyParameters
    {
        $gamma = Helper::readMPI($bytes);
        $phi = Helper::readMPI(substr($bytes, $gamma->getLengthInBytes() + 2));
        return new ElGamalSessionKeyParameters($gamma, $phi);
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->gamma->getLength()),
            $this->gamma->toBytes(),
            pack('n', $this->phi->getLength()),
            $this->phi->toBytes(),
        ]);
    }

    /**
     * Gets gamma
     *
     * @return BigInteger
     */
    public function getGamma(): BigInteger
    {
        return $this->gamma;
    }

    /**
     * Gets phi
     *
     * @return BigInteger
     */
    public function getPhi(): BigInteger
    {
        return $this->phi;
    }
}
