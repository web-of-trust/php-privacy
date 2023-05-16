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

use OpenPGP\Common\Helper;
use OpenPGP\Enum\HashAlgorithm;

/**
 * EdDSA public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class EdDSAPublicParameters extends ECPublicParameters implements VerifiableParametersInterface
{
    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return EdDSAPublicParameters
     */
    public static function fromBytes(string $bytes): EdDSAPublicParameters
    {
        $length = ord($bytes[0]);
        return new EdDSAPublicParameters(
            substr($bytes, 1, $length),
            Helper::readMPI(substr($bytes, $length + 1))
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature
    ): bool
    {
        $r = Helper::readMPI($signature);
        $s = Helper::readMPI(substr($signature, $r->getLengthInBytes() + 2));
        return $this->getPublicKey()->verify(
            hash(strtolower($hash->name), $message, true),
            implode([$r->toBytes(), $s->toBytes()])
        );
    }
}
